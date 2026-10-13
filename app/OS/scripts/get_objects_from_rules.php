<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
$projectName = 'project_name';  //Provide the project's name
$user = "admin"; // user to execute the script

// CODE STARTS HERE

class GetObjectsFromRules
{
    /* @var $projectName String */
    protected $projectName = '';

    /* @var mysqli $projectDB */
    protected $projectDB = null;

    protected $error=false;
    protected $errorMessage='';
    protected $rule_id;
    protected $field;


    public function __construct(string $name, array $params)
    {
        global $app;

        if($user = $app->container->sentinel->findByCredentials(['email' => $params['user']])) {
            $app->sentinel->login($user);
        }
        else{
            $this->error=true;
            $this->errorMessage='User not found';
        }


        $this->rule_id = $params['rule_id'];
        $this->field = $params['field'];
        $this->projectName= $name;
        $this->projectDB = selectDatabase($this->projectName);
        //echo "\n Auto saving snapshot\n";
        //take_snapshot_last($this->projectName);

    }

    public function execute(){


        if($this->error){
            echo $this->errorMessage."\n";
            exit(-1);
        }

        if($this->field == "service"){

                $query = "SELECT member_lid, table_name FROM security_rules_srv where rule_lid = '$this->rule_id'";
                $services = $this->projectDB->query($query);
                $map = array();
                $map_csv = "name;protocol_port;tag;description" . PHP_EOL;
                while($srv = $services->fetch_assoc()) {
                    $table_name = $srv['table_name'];
                    $lid = $srv['member_lid'];
                    if($table_name=="services"){
                        $query = "SELECT name, dport, protocol, override, timeout, halfclose_timeout, timewait_timeout, description  FROM services where id = '$lid'";
                        $data = $this->projectDB->query($query);
                        while($row = $data->fetch_assoc()) {
                            $map['service'][$row['name']]['name']=$row['name'];
                            $map['service'][$row['name']]['dport']=$row['dport'];
                            $map['service'][$row['name']]['protocol']=$row['protocol'];
                            $map['service'][$row['name']]['override']=$row['override'];
                            $map['service'][$row['name']]['timeout']=$row['timeout'];
                            $map['service'][$row['name']]['halfclose_timeout']=$row['halfclose_timeout'];
                            $map['service'][$row['name']]['timewait_timeout']=$row['timewait_timeout'];
                            $map['service'][$row['name']]['description']=$row['description'];

                            //name;protocol_port;tag;description
                            //service_tcp_1688;tcp/1688;;Imported
                            $map_csv.= "service_".$row['protocol']."_".$row['dport'].";".$row['protocol']."/".$row['dport'].";;"."Imported. Checkpoint_name=".$row['name']. PHP_EOL;
                        }

                    }elseif ($table_name=="services_groups_id"){
                        $query = "SELECT name, type, description FROM services_groups_id where id = '$lid'";
                        $data = $this->projectDB->query($query);
                        while($row = $data->fetch_assoc()) {
                            $map['service_group'][$row['name']]['name']=$row['name'];
                            $map['service_group'][$row['name']]['type']=$row['type'];
                            $map['service_group'][$row['name']]['description']=$row['description'];
                            $sg_name = $row['name'];
                            $query = "SELECT * FROM services_groups g, services s where g.lid = '$lid' and g.member_lid = s.id;";
                            $data = $this->projectDB->query($query);
                            while($row = $data->fetch_assoc()) {
                                $map['service_group'][$sg_name]['member'][$row['name']]['name']=$row['name'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['dport']=$row['dport'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['protocol']=$row['protocol'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['override']=$row['override'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['timeout']=$row['timeout'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['halfclose_timeout']=$row['halfclose_timeout'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['timewait_timeout']=$row['timewait_timeout'];
                                $map['service_group'][$sg_name]['member'][$row['name']]['description']=$row['description'];
                            }

                        }
                    }

                }

            }else{
                if($this->field == "source"){
                    $query = "SELECT member_lid, table_name FROM security_rules_src where rule_lid = '$this->rule_id'";
                }else{
                    $query = "SELECT member_lid, table_name FROM security_rules_dst where rule_lid = '$this->rule_id'";
                }

                $address = $this->projectDB->query($query);
                $map = array();
                $map_csv = "name;ipaddress;cidr;tag;description" . PHP_EOL;
                while($adr = $address->fetch_assoc()) {
                    $table_name = $adr['table_name'];
                    $lid = $adr['member_lid'];
                    if ($table_name == "address") {
                        $query = "SELECT name, type, ipaddress, cidr, description  FROM address where id = '$lid'";
                        $data = $this->projectDB->query($query);
                        while ($row = $data->fetch_assoc()) {
                            $map['address'][$row['name']]['name'] = $row['name'];
                            $map['address'][$row['name']]['type'] = $row['type'];
                            $map['address'][$row['name']]['ipaddress'] = $row['ipaddress'];
                            $map['address'][$row['name']]['cidr'] = $row['cidr'];
                            $map['address'][$row['name']]['description'] = $row['description'];

                            //name;ipaddress;cidr;tag;description
                            //Host_10.67.16.214;10.67.16.214;32;;Imported
                            //Network_10.75.0.0_16;10.75.0.0;16;;Imported
                            //FQDN-samur.emergencias.munimadrid.es;samur.emergencias.munimadrid.es;32;;Imported
                            if($row['type']=="ip-netmask"){
                                if($row['cidr']=="" || $row['cidr']=="32"){
                                    //Host_10.67.16.214;10.67.16.214;32;;Imported
                                    $map_csv.= "Host_".$row['ipaddress'].";".$row['ipaddress'].";32;;"."Imported. Checkpoint_name=".$row['name']. PHP_EOL;
                                }else{
                                    //Network_10.75.0.0_16;10.75.0.0;16;;Imported
                                    $map_csv.= "Network_".$row['ipaddress']."_".$row['cidr'].";".$row['ipaddress'].";".$row['cidr'].";;"."Imported. Checkpoint_name=".$row['name']. PHP_EOL;
                                }
                            }elseif ($row['type']=="fqdn"){
                                //FQDN-samur.emergencias.munimadrid.es;samur.emergencias.munimadrid.es;32;;Imported
                                $map_csv.= "FQDN-".$row['ipaddress'].";".$row['ipaddress'].";32;;"."Imported. Checkpoint_name=".$row['name']. PHP_EOL;
                            } else {
                                $this->error = true;
                                $this->errorMessage.= "Address typed as ". $row['type'] . "found" . PHP_EOL;
                            }

                        }

                    } elseif ($table_name == "address_groups_id") {
                        $query = "SELECT name, type, description FROM address_groups_id where id = '$lid'";
                        $data = $this->projectDB->query($query);
                        while ($row = $data->fetch_assoc()) {
                            $map['address_group'][$row['name']]['name'] = $row['name'];
                            $map['address_group'][$row['name']]['type'] = $row['type'];
                            $map['address_group'][$row['name']]['description'] = $row['description'];
                            $sg_name = $row['name'];
                            $query = "SELECT * FROM address_groups g, address s where g.lid = '$lid' and g.member_lid = s.id;";
                            $data = $this->projectDB->query($query);
                            while ($row = $data->fetch_assoc()) {
                                $map['address_group'][$sg_name]['member'][$row['name']]['name'] = $row['name'];
                                $map['address_group'][$sg_name]['member'][$row['name']]['type'] = $row['type'];
                                $map['address_group'][$sg_name]['member'][$row['name']]['ipaddress'] = $row['ipaddress'];
                                $map['address_group'][$sg_name]['member'][$row['name']]['cidr'] = $row['cidr'];
                                $map['address_group'][$sg_name]['member'][$row['name']]['description'] = $row['description'];
                            }

                        }
                    }
                }
        }

        echo json_encode($map,JSON_PRETTY_PRINT);
        echo  PHP_EOL. PHP_EOL. "========= CSV content ===========" .PHP_EOL;
        echo  $map_csv;
        echo  "========= /CSV content ===========";
        if($this->error) {
            echo PHP_EOL . PHP_EOL . $this->errorMessage;
        }
        echo PHP_EOL. PHP_EOL. "Script finished" .PHP_EOL. PHP_EOL;
        exit(1);

    }

}

global $app;

echo "Expedition rule objects extractor: " . PHP_EOL;

// Create a console prompt with the fun title
$param1 = readline("1) Please provide Expedition project name: ");
$param2 = readline("2) Please provide Rule id: ");
do {
    $param3 = readline("3) Please provide field to extract (source, destination, service): ");
    if($param3=="source" || $param3=="destination" || $param3=="service"){
        break;
    }
} while(true);

// Display the provided parameters
echo "- Project: " . $param1 . PHP_EOL;
echo "- Rule ID: " . $param2 . PHP_EOL;
echo "- Field: " . $param3 . PHP_EOL;

$continue = readline("Continue? (Y,n) ");

if($continue==="Y"){

    echo "Extraction started " . PHP_EOL;
    $projectName = $param1;
    $params = [
        'user'  => $user,
        'rule_id' => $param2,
        'field' => $param3
    ];
    $executor = new GetObjectsFromRules($projectName, $params);
    $executor->execute();

} else {
    echo "Action canceled " . PHP_EOL;
}