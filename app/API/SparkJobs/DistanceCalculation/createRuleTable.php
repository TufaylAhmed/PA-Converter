<?php

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once "./GetRules.php";
require_once INC_ROOT."/libs/projectdb.php";

$projectdb = selectDatabase("Improvement");
//$projectdb = selectDatabase("huge");
GetRules::createTempViewRules($projectdb, 1, "all", "a");
