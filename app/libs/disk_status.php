<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//require_once('../bin/Authentication.php');
require_once './DiskStatus.class.php';

try {
  	$diskStatus = new DiskStatus('/');

  	$freeSpace = $diskStatus->freeSpace();
  	$totalSpace = $diskStatus->totalSpace();
  	$barWidth = ($diskStatus->usedSpace()/100);
  	$other=100-$diskStatus->usedSpace();
	echo '[{"used":"'.$barWidth.'","pct":"'.$diskStatus->usedSpace().'"}]';
} catch (Exception $e) {
  echo 'Error while getting disk information';
  exit();
}

?>
