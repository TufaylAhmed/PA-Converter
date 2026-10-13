<?php

use cli\progress\Bar;
use function cli\line;

require_once 'common.php';


line('  Migrating Traffic Log files (csv)');
$path = $variables['CSVlogsPath'];
$notifyProjectFolder = new Bar("   Migrating $path folders ", 2);
$notifyProjectFolder->display();
$command_scp = "rsync -r -o -g ".escapeshellarg($path."/")." ".escapeshellarg($variables['sshUser']."@".$variables['ip'].":$path");
shell_exec($command_scp);
$msg = '     Traffic Log files migrated';
$notifyProjectFolder->tick(1, $msg);
$notifyProjectFolder->finish();

