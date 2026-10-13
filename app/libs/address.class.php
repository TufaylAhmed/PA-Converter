<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
class address {
	private $first_name, $last_name;
 
	public function setData($name, $ipaddress) {
		$this->name = $name;
		$this->ipaddress = $ipaddress;
	}
 
	public function printData() {
		echo $this->name . " : " . $this->ipaddress;
	}
}


$newAddress= new address();
$newAddress->setData("thename","1.1.1.1");
$newAddress2= new address();
$newAddress2->setData("thename","1.1.1.1");
echo $newAddress->printData();
?>