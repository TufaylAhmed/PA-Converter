<?php

require_once 'common.php';

\cli\Colors::enable(); // Forcefully enable
echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";
echo \cli\Colors::colorize('  %C%9|%n                                WELCOME TO THE EXPEDITION TRANSFER ASSISTANT                                      %C%9|%n',true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   This tool will help you transferring your current projects and data between two Expedition instances,          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   being this one the Source (%B%9Machine_A%n) to a new Expedition (%C%9Machine_B%n).                                         %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 1%n: Create a private-public SSH key.                                                                       %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     Using your %B%9\'root\'%n user, execute the following command in this Expedition VM (Machine_A) and follow           %C%9|%n',true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     the default instructions:                                                                                    %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     ssh-keygen -o                                                                                           %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     This will generate a pair public-private keys tow SSH communications with the destination Expedition         %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     Show the content of your public key via the command :                                                        %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     cat ~/.ssh/id_rsa.pub                                                                                   %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 2%n: Add (%B%9Machine_A%n) as a trusted ssh client in %C%9Machine_B                                                   %C%9|%n',true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     On your destination Expedition (Machine_B) as root, edit the authoritzed keys list with the command          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     nano /.ssh/authorized_keys                                                                              %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     and add the public key from Machine_A. Make sure that no spaces are present in the added line                %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 3%n: Test the connection                                                                                    %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     Test that your public-private keys are correctly set to SSH between the machines. From Machine_A execute:    %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     ssh root@%C%9Machine_B                                                                                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     This will establish an SSH authenticated connection WITHOUT requestion your root password                    %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n   %G%9Step 4%n: Allow remote MySQL connection                                                                          %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     On your destination Expedition %C%9Machine_B%n, enter to mysql using the default credentials                       %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     mysql -uroot -ppaloalto mysql                                                                           %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     And execute the following SQL statements (you may set the IP address of your %B%9Machine_A%n)                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     GRANT ALL PRIVILEGES ON *.* TO \'root\'@\'192.168.%.%\' IDENTIFIED BY \'paloalto\' WITH GRANT OPTION; %n        %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     FLUSH PRIVILEGES; %n                                                                                      %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n     %R%9     exit; %n                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";








