<?php

use function cli\line;
require_once './options/common.php';

line();
echo \cli\Colors::colorize('%C%9Settings%n', true) . "\n";
echo "  IP address:\t".$variables['ip']."\n";
line();
echo \cli\Colors::colorize('%R%9SSH%n (mandatory)', true) . "\n";
echo "     user:\t".$variables['sshUser']."\n";
echo "     password:\tprivate-public keys\n";
echo "     port:\t22\n";
line();
echo \cli\Colors::colorize('%R%9Database%n', true) . "\n";
echo "     user:\t".$variables['mysqlUser']."\n";
echo "     password:\t".$variables['mysqlPass']."\n";
echo "     port:\t".$variables['mysqlPort']."\n";
line();
echo \cli\Colors::colorize('%R%9ML%n', true) . "\n";
echo "     Traffic Logs path:\n";
echo "     connections.parquet path:\t ".$variables['connections_parquet']."\n";
line();
