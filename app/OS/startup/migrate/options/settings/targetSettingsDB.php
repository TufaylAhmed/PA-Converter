<?php

use cli\Streams;
use function cli\line;

require_once './options/common.php';

echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9INSTRUCTIONS                                                                                                   %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 1%n: Allow remote MySQL connection                                                                          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     On your destination Expedition %C%9Machine_B%n, enter to mysql using the default credentials (root:paloalto)       %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     In case you defined different user and password, modify the SQL statements to make them match.               %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     mysql -uroot -ppaloalto mysql                                                                           %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     And execute the following SQL statements (you may set the IP address of your %B%9Machine_A%n)                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     GRANT ALL PRIVILEGES ON *.* TO \'root\'@\'192.168.%.%\' IDENTIFIED BY \'paloalto\' WITH GRANT OPTION; %n        %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     FLUSH PRIVILEGES; %n                                                                                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     exit; %n                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 2%n: Allow remote MySQL connection                                                                          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     Open firewall-cmd to allow remote MySQL connections. On the remote Expedition:                               %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     firewall-cmd --add-port=3306/tcp                                                                        %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 3%n: Allow remote MySQL connection                                                                          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     Complete the form below                                                                                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";

line('Enter the DB User for remote connection [root]:');
$user = Streams::input();
$variables['mysqlUser'] = $user === ''?'root':$user;

line('Enter the DB Password [paloalto]:');
$password = Streams::input();
$variables['mysqlPass'] = $password === ''?'paloalto':$password;

line('Enter the DB port [3306]:');
$port = Streams::input();
$variables['mysqlPort'] = $port === ''?'3306':$port;

$userSettingsFile = fopen($userDefinitionsPath, 'wb');
fwrite($userSettingsFile, json_encode($variables));
fclose($userSettingsFile);

