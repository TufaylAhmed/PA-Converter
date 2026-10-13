<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 4:47 PM
 ******************************************************************************/

require_once INC_ROOT.'/libs/objects/tools/usage/locations/ZoneLocations.php';

class ZoneUsage {
    /** @var String $name
     * @var ZoneLocations[] $locations
     * @var mysqli $connection
     * @var string $vsys
     * @var int $template
     * @var int $source
     */
    private $objectType = "zones";
    private $name;
    private $locations;
    private $connection;
    private $source;
    private $vsys;
    private $template;

    public function __construct(mysqli $connection, int $source, String $vsys, int $template){
        $this->setdbConnection($connection);
        $this->setSource($source);
        $this->setVsys($vsys);
        $this->setTemplate($template);
        $this->locations = new ZoneLocations();
    }

    public function getDynamicGridMetadata(String $root, String $title){
        return [
            "windowTitle" => $title,
            "objectType"    => $this->objectType,

            "idProperty"=> "id",
            "totalProperty"=> "total",
            "successProperty"=> "success",

            "root"=> $root,

            "fields"=> [
                [
                    "name" => "id",
                    "type"  => "int",
                    "allowBlank"    => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name"=> "name",
                    "type"=> "string",
                    "allowBlank"=> false,
                    "defaultValue"=> "0"
                ],
                [
                    "name" => "total",
                    "type"=> "auto",
                    "mapping" => "amount",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],

                [
                    "name" => "appoverride_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "appoverride_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "authentication_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "authentication_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "decryption_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "decryption_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "dos_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "dos_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "interfaces",
                    "type"=> "auto",
                    "mapping" => "amount",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "nat_rules",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "nat_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "pbf_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "qos_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "qos_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "security_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "security_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "tunnel_inspect_rules_from",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ],
                [
                    "name" => "tunnel_inspect_rules_to",
                    "type"=> "auto",
                    "allowBlank" => false,
                    "defaultValue"  => "0"
                ]
            ],
            "columns"=> [
                declareHiddenCellFormat("id", "ID"),
                declareCellFormatHeader("name", "Name", true),
                declareCellFormat("total","Total", true),

                declareCellFormat("interfaces","Interfaces"),
                [
                    "header"=> "Security Rules",
                    "columns" => [
                        declareCellFormat("security_rules_from","From"),
                        declareCellFormat("security_rules_to","To"),]
                ],
                [
                    "header"=> "Nat Rules",
                    "columns" => [
                        declareCellFormat("nat_rules_from","From"),
                        declareCellFormat("nat_rules","To"),
                    ]
                ],
                [
                    "header"=> "Application Override",
                    "columns" => [
                        declareCellFormat("appoverride_rules_from","From"),
                        declareCellFormat("appoverride_rules_to","To"),
                    ]
                ],
                [
                    "header"=> "Authentication Rules",
                    "columns" => [
                        declareCellFormat("authentication_rules_from","From"),
                        declareCellFormat("authentication_rules_to","To"),
                    ]
                ],
                [
                    "header"=> "Decryption Rules",
                    "columns" => [
                        declareCellFormat("decryption_rules_from","From"),
                        declareCellFormat("decryption_rules_to","To"),
                    ]
                ],
                [
                    "header"=> "DoS Rules",
                    "columns" => [
                        declareCellFormat("dos_rules_from","From"),
                        declareCellFormat("dos_rules_to","To"),
                    ]
                ],
                declareCellFormat("qos_rules_from","QoS"),
                declareCellFormat("pbf_rules_from","PBF"),
                [
                    "header"=> "Tunnel Inspection Rules",
                    "columns" => [
                        declareCellFormat("tunnel_inspect_rules_from","From"),
                        declareCellFormat("tunnel_inspect_rules_to","To"),
                    ]
                ],
            ]
        ];
    }

    public function setdbConnection(mysqli $connection){
        $this->connection = $connection;
    }

    public function setSource(int $source){
        $this->source = $source;
    }

    public function setVsys(String $vsys){
        $this->vsys = $vsys;
    }

    public function setTemplate(int $template){
        $this->template = $template;
    }

    public function setName(String $name){
        $this->name = $name;
    }

    public function getName():String{
        return $this->name;
    }

    public function locations():ZoneLocations{
        return $this->locations;
    }

    public function getTotalUsage():int{
        $total = 0;
        /**
         * @var ZoneLocation $zoneLocation
         */
        foreach ($this->locations->getOptions() as $zoneLocation){
            $total += $this->locations()->get($zoneLocation)->getAmount();
        }
        return $total;
    }

    public function getTotal_TotalRiskUsage():array{
        $totals = [0,0];
        /**
         * @var ZoneLocation $zoneLocation
         */
        foreach ($this->locations->getOptions() as $zoneLocation){
            $totals = array_map(function (...$arrays) {
                return array_sum($arrays);
            }, $totals, $this->locations()->get($zoneLocation)->getAmount_RiskAmount());
        }

        return [
            "amount" => $totals[0],
            "riskAmount"=>$totals[1],
            "objectType"=>$this->objectType,
            "locationType"=>$this->table_name,
        ];
    }

    public function getLocationsWhereUsed():array{
        $usedIn = array();
        /**
         * @var String $key
         * @var ZoneLocation $zoneLocation
         */
        foreach ($this->locations->getOptions() as $zoneLocation){
            if($this->locations->get($zoneLocation)->getAmount()>0)
                $usedIn[] = $this->locations->get($zoneLocation)->getName();
        }
        return $usedIn;
    }

    private function getEntries(String $query){
        $result = $this->connection->query($query);
        if($result->num_rows>0) {
            $data = $result->fetch_array();
            return $data[0];
        }
        return 0;
    }

    public function updateInterfaceUsage(){
        $amountZones=$this->getEntries("SELECT count(*) as amount FROM interfaces WHERE template='$this->template' AND zone='$this->name' AND source='$this->source';");
        $this->locations()->get('interfaces')->setAmount($amountZones);
        $this->locations()->get('interfaces')->setRiskAmount($amountZones);
    }

    public function updateSecurityRuleFromUsage(){
        $ids_rules = getIdsBySourceVsys("security_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('security_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM security_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM security_rules_from
                          WHERE rule_lid in (
                            SELECT rule_lid FROM security_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()->get('security_rules_from')->setRiskAmount($this->getEntries($queryRisk));
        }

    }

    public function updateSecurityRuleToUsage(){
        $ids_rules = getIdsBySourceVsys("security_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()->get('security_rules_to')->setAmount($this->getEntries("SELECT count(*) as amount FROM security_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM security_rules_to
                          WHERE rule_lid in (
                            SELECT rule_lid FROM security_rules_to WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()->get('security_rules_to')->setRiskAmount($this->getEntries($queryRisk));
        }
    }

    public function updateSecurityRuleUsage(){
        $ids_rules = getIdsBySourceVsys("security_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('security_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM security_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM security_rules_from
                          WHERE rule_lid in (
                            SELECT rule_lid FROM security_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()->get('security_rules_from')->setRiskAmount($this->getEntries($queryRisk));

            $this->locations()
                ->get('security_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM security_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM security_rules_to
                          WHERE rule_lid in (
                            SELECT rule_lid FROM security_rules_to WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()
                ->get('security_rules_to')
                ->setRiskAmount($this->getEntries($queryRisk));
        }
    }

    public function updateNatRuleFromUsage(){
        $ids_rules = getIdsBySourceVsys("nat_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()->get('nat_rules_from')->setAmount($this->getEntries("SELECT count(*) as amount FROM nat_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM nat_rules_from
                          WHERE rule_lid in (
                            SELECT rule_lid FROM nat_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()->get('nat_rules_from')->setRiskAmount($this->getEntries($queryRisk));
        }
    }

    public function updateNatRuleToUsage(){
        $natToAmount = $this->getEntries("SELECT count(*) as amount FROM nat_rules      WHERE source='$this->source' AND vsys='$this->vsys' AND op_zone_to='$this->name';");
        $this->locations()->get('nat_rules')->setAmount($natToAmount);
        $this->locations()->get('nat_rules')->setRiskAmount($natToAmount);
    }

    public function updateNatRuleUsage(){
        $ids_rules = getIdsBySourceVsys("nat_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()->get('nat_rules_from')->setAmount($this->getEntries("SELECT count(*) as amount FROM nat_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $queryRisk = "SELECT COUNT(*) FROM (
                          SELECT rule_lid, count(*) as numberZones
                          FROM nat_rules_from
                          WHERE rule_lid in (
                            SELECT rule_lid FROM nat_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ")
                          )
                          GROUP BY rule_lid
                          HAVING numberZones = 1
                      ) as a";
            $this->locations()->get('nat_rules_from')->setRiskAmount($this->getEntries($queryRisk));

            $natToAmount = $this->getEntries("SELECT count(*) as amount FROM nat_rules      WHERE source='$this->source' AND vsys='$this->vsys' AND op_zone_to='$this->name';");
            $this->locations()->get('nat_rules')->setAmount($natToAmount);
            $this->locations()->get('nat_rules')->setRiskAmount($natToAmount);
        }
    }

    public function updateAppoverrideRuleUsage(){
        $ids_rules = getIdsBySourceVsys("appoverride_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('appoverride_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM appoverride_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('appoverride_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM appoverride_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }

    }

    public function updateAuthenticationRuleUsage(){
        $ids_rules = getIdsBySourceVsys("authentication_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('authentication_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM authentication_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('authentication_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM authentication_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }

    }

    public function updatedDecryptionRuleUsage(){
        $ids_rules = getIdsBySourceVsys("authentication_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('decryption_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM decryption_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('decryption_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM decryption_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }

    }

    public function updatedDoSRuleUsage(){
        $ids_rules = getIdsBySourceVsys("dos_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('dos_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM dos_rules_from WHERE name='$this->name' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('dos_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM dos_rules_to   WHERE name='$this->name' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }
    }

    public function updatedQoSRuleUsage(){
        $ids_rules = getIdsBySourceVsys("qos_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('qos_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM qos_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('qos_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM qos_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }
    }

    public function updatedPBFRuleUsage(){
        $ids_rules = getIdsBySourceVsys("pbf_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('pbf_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM pbf_rules_from WHERE name='$this->name' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }
    }

    public function updatedTunnelInspectRuleUsage(){
        $ids_rules = getIdsBySourceVsys("tunnel_inspect_rules", $this->source, $this->vsys);
        if(count($ids_rules) > 0) {
            $this->locations()
                ->get('qos_rules_from')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM tunnel_inspect_rules_from WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
            $this->locations()
                ->get('qos_rules_to')
                ->setAmount($this->getEntries("SELECT count(*) as amount FROM tunnel_inspect_rules_to   WHERE name='$this->name' AND rule_lid IN (" . implode(',', $ids_rules) . ");"));
        }
    }

    public function calculateUsage(){
        if(!isset($this->source) || !isset($this->vsys) || !isset($this->template) || !isset($this->connection))
            return;

        $this->updateInterfaceUsage();
        $this->updateSecurityRuleUsage();
        $this->updateNatRuleUsage();
        $this->updateAppoverrideRuleUsage();
        $this->updateAuthenticationRuleUsage();
        $this->updatedDecryptionRuleUsage();
        $this->updatedDoSRuleUsage();
        $this->updatedQoSRuleUsage();
        $this->updatedPBFRuleUsage();
        $this->updatedTunnelInspectRuleUsage();
    }
}