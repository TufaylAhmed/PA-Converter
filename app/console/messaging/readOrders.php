<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 2/6/16 - 11:09
 */

require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/libs/vendor/autoload.php';

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';

use PaloAltoNetworks\AmqpWrapper\SimpleReceiver;

$receiver = new SimpleReceiver();
$receiver->listen();