<?php

include_once '/home/userSpace/userDefinitions.php';
use cli\progress\Bar;
use function cli\line;

/***
 * Transfer the pandbRBAC to the destination Expedition
 * @param $variables
 * @return bool
 */
function transfer_pandbRBAC($variables):bool{
    line('  Migrating RBAC settings');
    $notifyRBAC = new Bar('   Migrating RBAC settings ', 3);
    $notifyRBAC->display();

    $msg = '     RBAC - Creating backup';
    $notifyRBAC->tick(1, $msg);
    $path_pandbRBAC = '/tmp/pandbRBAC_dump.sql';
    $command = "mysqldump -u".DBUser." -p".DBPass." pandbRBAC > $path_pandbRBAC";
    $response = exec($command);

    $msg = '     RBAC - Applying backup on destination';
    $notifyRBAC->tick(1, $msg);

    $command2 = "mysql -h ".$variables['ip']." -u".$variables['mysqlUser']." -p".$variables['mysqlPass']." pandbRBAC < $path_pandbRBAC";
    $response = exec($command2);
    $msg = '     RBAC - Transfer completed';
    $notifyRBAC->tick(1, $msg);
    $notifyRBAC->finish();
    unlink($path_pandbRBAC);

    return true;
}

/***
 *
 * @param $variables
 * @return bool
 */
function migrateProjects($variables):bool{
    global $app;
    line('  Migrating Projects');

    $projects = $app->project->orderBy('name')->get();
    foreach ($projects as $project){
        $project_name = $project->name;
        $notifyProject = new Bar('   Migrating project '.$project_name, 4);
        $notifyProject->display();

        $msg = sprintf('     %s - Creating backup', $project_name);
        $notifyProject->tick(1, $msg);
        $pathProject = '/tmp/project_dump.sql';
        $command_dump = "mysqldump -u".DBUser." -p".DBPass." $project_name > $pathProject";
        $response = exec($command_dump);

        $msg = sprintf('     %s - Creating project in destination', $project_name);
        $notifyProject->tick(1, $msg);
        $command_create = "mysql -h ".$variables['ip']." -u".$variables['mysqlUser']." -p".$variables['mysqlPass']." -e \"CREATE DATABASE IF NOT EXISTS $project_name\"";
        $response = exec($command_create);

        $msg = sprintf('     %s - Applying backup on destination', $project_name);
        $notifyProject->tick(1, $msg);
        $command_restore = "mysql -h ".$variables['ip']." -u".$variables['mysqlUser']." -p".$variables['mysqlPass']." $project_name < $pathProject";
        $response = exec($command_restore);

        $msg = sprintf('     %s - Transfer completed', $project_name);
        $notifyProject->tick(1, $msg);
        $notifyProject->finish();
        unlink($pathProject);
    }

    $notifyProjectFolder = new Bar('   Migrating Project folders ', 1);
    $notifyProjectFolder->display();
    $command_scp = "rsync -r -o -g /home/userSpace/projects ".escapeshellarg($variables['sshUser']."@".$variables['ip'].":/home/userSpace/");
    shell_exec($command_scp);
    $msg = '     Projects folders migrated';
    $notifyProjectFolder->tick(1, $msg);
    $notifyProjectFolder->finish();
    return true;
}

/***
 *
 * @param $variables
 * @return bool
 */
function migrateDevices($variables):bool{
    line('  Migrating Devices');

    $notifyProjectFolder = new Bar('   Migrating Device folders ', 1);
    $notifyProjectFolder->display();
    $command_scp = "rsync -r -o -g /home/userSpace/devices ". escapeshellarg($variables['sshUser']."@".$variables['ip'].":/home/userSpace/");
    shell_exec($command_scp);
    $msg = '     Devices folders migrated';
    $notifyProjectFolder->tick(1, $msg);
    $notifyProjectFolder->finish();

    return true;
}
