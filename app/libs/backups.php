<?php
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 11/23/16
 * Time: 5:30 PM
 */

require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';
require_once INC_ROOT.'/libs/database.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

/***
 * Encrypts a SQL dump into a new file with the .dat extension
 * @param OpenSSLTools $encryptor
 * @param STRING $path
 */
function encryptSnapshot(OpenSSLTools $encryptor, STRING $path){
    $encryptor->encryptFiletoFile($path, "$path.dat");
    unlink($path);
}

function decryptSnapshot(OpenSSLTools $encryptor, STRING $path, STRING $destination){
    $encryptor->decryptFileFromFile($path, $destination);
}

/***
 * Creates a DB project snapshot and stores it encrypted with the keys for the project.
 * If a prior snapshot exists, it will be overwritten
 * @param STRING $project
 */
function take_snapshot_last(STRING $project) {
    global $app;
    //$file = USERSPACE_PATH."/projects/$project/Backups/undo_MT_".date("Y-m-d_H-i-s").".sql";
    $projectObj = $app->project->where("name",$project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    //_MT_".date("Y-m-d_H-i-s").".sql";
    $file = USERSPACE_PATH."/projects/$project/Backups/undo_MT_".date("Y-m-d_H-i-s").".sql";

    $mysqldump_file = create_mysql_dump_file();

    //$Command = "mysqldump -u ".DBUser." -p".DBPass." $project > ".$file;
    $Command = "mysqldump --defaults-extra-file=$mysqldump_file $project > $file";
    exec($Command);

    delete_mysql_dump_file($mysqldump_file);

//    exec($Command, $output, $error_code);

    encryptSnapshot($encryptor, $file);

    //If we have any redo files, delete them
    $file = USERSPACE_PATH."/projects/$project/Backups/redo";
    $list = glob($file."*.sql.dat");
    $numberOfUndos = count($list);
    if($numberOfUndos>0) {
        foreach ($list as $item) {
            unlink($item);
        }
    }

    //If we have more than 5 undo files, delete the oldest ones
    deleteOlderBackups($project, "undo_MT_");
}

function deleteOlderBackups(STRING $project, STRING $prefix){
    //If we have more than 5 undo files, delete the oldest ones
    $file = USERSPACE_PATH."/projects/$project/Backups/$prefix";
    $list = glob($file."*.sql.dat");
    $numberOfUndos = count($list);
    if($numberOfUndos>4) {
        $i=0;
        foreach ($list as $item) {
            if($i < $numberOfUndos - 5) {
                unlink($item);
            }
            $i++;
        }
    }
}

/***
 * @param STRING $project
 * @param STRING $snapshot
 */
function load_snapshot(STRING $project, STRING $snapshot) {
    require_once INC_ROOT.'/libs/common/definitions.php';

    global $app;
    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    $file = USERSPACE_PATH."/projects/$project/Backups/$snapshot";
    if(strpos($snapshot, ".sql.dat")===false) {
        $list = glob($file . "_MT_*.sql.dat");
    }
    else{
        $list = glob($file);
    }
    if(count($list)==1) {
        $snapshotName = $list[0];
        $backupName = USERSPACE_PATH."/projects/$project/Backups/backup.sql";
        decryptSnapshot($encryptor, $snapshotName, $backupName);

        $mysql_file= create_mysql_file();
        $Command = "mysql --defaults-extra-file=$mysql_file $project < $backupName";
        //$Command = "mysql -u ".DBUser." -p".DBPass." $project <  $backupName";
        exec($Command);
        delete_mysql_dump_file($mysql_file);
        unlink($backupName);
        reactivate_RealTimeUpdate_changes($project, $snapshotName);
        echo json_encode(array("success" => true, "msg" => "Snapshot correctly Loaded."));
    }
    else{
        echo json_encode(array("success" => false, "msg" => "File not found"));
    }

}


function verifySpace(STRING $project) {
    $existingSnapshots = list_snapshots($project);
    if($existingSnapshots['total']>= 20){
        return [
            'code'  => false,
            'msg'   => 'Please, delete some existing snapshots'
        ];
    }

    return [
        'code'  => true,
        'msg'   => 'Verification succeded'
    ];
}
/***
 * Takes a snapshot on demand and encrypts it with the keys for the project
 * If there is a prior snapshot with the same name (excluding the time), it overwrites it
 * @param STRING $project
 * @param STRING $snapshot_name
 */
function take_snapshot(STRING $project, STRING $snapshot_name) {
    global $app;
    require_once INC_ROOT.'/libs/shared.php';
    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

//    require_once INC_ROOT.'/libs/projectdb.php';
//    $projectdb = selectDatabase($project);
    //date_default_timezone_set('Europe/Madrid');
    $snapshot_name = normalizeNames($snapshot_name);
    $snapshot_name = str_replace(' ', '_', $snapshot_name);

    $mysql_dump_file= create_mysql_dump_file();

    if($snapshot_name != ""){
        $file = USERSPACE_PATH."/projects/$project/Backups/$snapshot_name";
        $list = glob($file."_MT_*.sql.dat");
        if(count($list)==1){
            //Delete the prior dump with the same filename
            unlink($list[0]);
        }
        $filePath = $file."_MT_".date("Y-m-d_H-i-s").".sql";
        //$Command = "mysqldump -u ".DBUser." -p".DBPass." $project > $filePath";
        $Command = "mysqldump --defaults-extra-file=$mysql_dump_file $project > $filePath";
        exec($Command);
        encryptSnapshot($encryptor, $filePath);
    }
    else{
        $filename = $project . "_" . date("Y-m-d_H-i-s") . ".sql";
        $filePath = USERSPACE_PATH."/projects/$project/Backups/" . $filename;
        //$Command = "mysqldump -u ".DBUser." -p".DBPass." $project > $filePath";
        $Command = "mysqldump --defaults-extra-file=$mysql_dump_file $project > $filePath";
        exec($Command);
        encryptSnapshot($encryptor, $filePath);
    }

    delete_mysql_dump_file($mysql_dump_file);

    if($snapshot_name != "last_saved"){  //Even the dump is not a UNDO instance, create a new file (overwriting prior ones) to show the UNDO dump
        //If we have any redo files, delete them
        $file = USERSPACE_PATH."/projects/$project/Backups/redo";
        $list = glob($file."*.sql.dat");
        $numberOfUndos = count($list);
        if($numberOfUndos>0) {
            foreach ($list as $item) {
                unlink($item);
            }
        }

        deleteOlderBackups($project, "undo");
        //

        $filename = "undo_MT_".date("Y-m-d_H-i-s").".sql.dat";
        $filePathLastDump = USERSPACE_PATH."/projects/$project/Backups/$filename";
        copy("$filePath.dat",$filePathLastDump);
    }

    echo json_encode(array("success" => true, "msg" => "Snapshot Created."));
}

/***
 * List the different backups we have for the current project.
 * @param $project
 */
function list_snapshots(STRING $project) {
    $ProjectFolders = USERSPACE_PATH."/projects/$project/Backups";
    $files1 = scandir($ProjectFolders);
    $files = array_diff($files1, array('.', '..'));
    $arrayNames = array();
    foreach ($files1 as $file){
        $fileName = explode("_MT_", $file);
        $arrayNames[$fileName[0]] = [
            "name" => $fileName[0]
            ];
    }
    $printableNames = array();

    //Remove entries that should not be presented in the list
    unset($arrayNames["."]);
    unset($arrayNames[".."]);
    unset($arrayNames["redo"]);
    unset($arrayNames["undo"]);

    //Remove the keys to build the correct json structure
    foreach ($arrayNames as $key=>$name){
        $printableNames[] = $name;
    }

    $output = [
        "total" => count($printableNames),
        "snapshots" => $printableNames
    ];
    return $output;
//    echo json_encode($output);
}

/***
 * Makes a Ctrl+Shift+Z to restore the last undo
 * @param $project
 */
function load_next_saved(STRING $project){
    global $app;
    require_once INC_ROOT.'/libs/common/definitions.php';

    $file = USERSPACE_PATH."/projects/$project/Backups/redo";
    $list = glob($file."_MT_*.sql.dat");
    $numberOfUndos = count($list);
    if($numberOfUndos>0){
        $snapshotName = $list[0];

        $decryptedName = USERSPACE_PATH."/projects/$project/Backups/decrypted.sql";

        $projectObj = $app->project->where("name",$project)->first();
        $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
        $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);
        $encryptor->decryptFileFromFile($snapshotName, $decryptedName);

        $mysql_file= create_mysql_file();
        $Command = "mysql --defaults-extra-file=$mysql_file $project < $decryptedName";
        //$Command = "mysql -u ".DBUser." -p".DBPass." $project <  $decryptedName";
        exec($Command);
        unlink($decryptedName);
        delete_mysql_dump_file($mysql_file);

        //Look for a "current" file and change it to "undo"
        $file = USERSPACE_PATH."/projects/$project/Backups/current";
        $list = glob($file."_MT_*.sql.dat");
        if(isset($list[0])){
            preg_match("/current_MT_(.*)\.sql\.dat/", $list[0], $output_array);
            $newName = USERSPACE_PATH."/projects/$project/Backups/undo_MT_$output_array[1].sql.dat";
            rename($list[0], $newName);
        }

        //The "redo" we just applied becomes the new "current"
        preg_match("/redo_MT_(.*)\.sql\.dat/", $snapshotName, $output_array);
        $newName = USERSPACE_PATH."/projects/$project/Backups/current_MT_$output_array[1].sql.dat";
        rename($snapshotName, $newName);

        reactivate_RealTimeUpdate_changes($project, $snapshotName);
        return  [
            "code"   => true,
            "msg"       => "Next Redo was Loaded."
        ];
    }
    else{
        return [
            "code" => false,
            "msg" => "No Redo found"
        ];
    }
}

/***
 * Restores the last saved backup (via decrypt), and renames the last saved backup into first forward backup
 * In other words, makes a Ctrl+z
 * @param $project
 */
function load_last_saved($project) {
    global $app;
    require_once INC_ROOT.'/libs/common/definitions.php';

    $projectObj = $app->project->where("name",$project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    //Check if there is any redo. If not, the current status will be for the next redo
    $file = USERSPACE_PATH."/projects/$project/Backups/redo";
    $list = glob($file."_MT_*.sql.dat");
    $numberOfRedos = count($list);

    if($numberOfRedos==0) {
        $mysql_dump_file= create_mysql_dump_file();
        $filename = "redo_MT_" . date("Y-m-d_H-i-s") . ".sql";
        $filePath = USERSPACE_PATH."/projects/$project/Backups/" . $filename;
        //$Command = "mysqldump -u ".DBUser." -p".DBPass." $project > $filePath";
        $Command = "mysqldump --defaults-extra-file=$mysql_dump_file $project > $filePath";
        exec($Command);
        encryptSnapshot($encryptor, $filePath);
        delete_mysql_dump_file($mysql_dump_file);
    }

    $file = USERSPACE_PATH."/projects/$project/Backups/undo";
    $list = glob($file."_MT_*.sql.dat");
    $numberOfUndos = count($list);
    if($numberOfUndos>0){
        $snapshotName = $list[$numberOfUndos-1];

        $decryptedName = USERSPACE_PATH."/projects/$project/Backups/decrypted.sql";

        $encryptor->decryptFileFromFile($snapshotName, $decryptedName);
        $mysql_file= create_mysql_file();
        //$Command = "mysql -u ".DBUser." -p".DBPass." $project <  $decryptedName";
        $Command = "mysql --defaults-extra-file=$mysql_file $project < $decryptedName";
        exec($Command);
        unlink($decryptedName);
        delete_mysql_dump_file($mysql_file);


        //Look for a "current" file and change it to "redo"
        $file = USERSPACE_PATH."/projects/$project/Backups/current";
        $list = glob($file."_MT_*.sql.dat");
        if(isset($list[0])){
            preg_match("/current_MT_(.*)\.sql\.dat/", $list[0], $output_array);
            $newName = USERSPACE_PATH."/projects/$project/Backups/redo_MT_$output_array[1].sql.dat";
            rename($list[0], $newName);
        }

        //The "undo" we just applied becomes the new "current"
        preg_match("/undo_MT_(.*)\.sql\.dat/", $snapshotName, $output_array);
        $newName = USERSPACE_PATH."/projects/$project/Backups/current_MT_$output_array[1].sql.dat";
        rename($snapshotName, $newName);

        reactivate_RealTimeUpdate_changes($project, $snapshotName);
        return  [
            "code"   => true,
            "msg"       => "Last Config Saved was Loaded."
        ];
    }
    else{
        return [
            "code" => false,
            "msg" => "No Undo found"
        ];
    }
}

function reactivate_RealTimeUpdate_changes(STRING $project, STRING $snapshot){
    require_once INC_ROOT.'/libs/common/definitions.php';
    require_once INC_ROOT.'/libs/projectdb.php';
    $RTUpdatesDB = selectDatabase('RealTimeUpdates');

    $snapshotArr = explode("_MT_",$snapshot);
    $snapshotArr2 = explode('.', $snapshotArr[1]);
    preg_match("/(.*)-(.*)-(.*)_(.*)-(.*)-(.*)/", $snapshotArr2[0], $o);
    $date_snapshot = date("Y-m-d H:i:s", mktime($o[4],$o[5],$o[6],$o[2],$o[3],$o[1]));

    $query = "SELECT id, projects FROM firewallUpdates WHERE projects LIKE '%\"$project\"%'";
    $result = $RTUpdatesDB->query($query);
    $projectsAffected = array();
    if($result->num_rows>0){
        while($data = $result->fetch_assoc()){
            //For each change...
            $projectsString = $data['projects'];
            $id = $data['id'];
            $projArray = json_decode($projectsString);
            $modified = false;
            foreach ($projArray as $projName => $data){
                //...look for the information regarding the rolled_back project
                if($projName == $project){
                    // When we are within the information regarding the rolled_back project
                    if($data->date != 'Pending') {
                        $date_applied_change = date($data->date);
                        //Check if the applied change was performed AFTER the date of the snapshot
                        if (strtotime($date_snapshot) <= strtotime($date_applied_change)) {
                            //If it was done after, we need to change the date of application to "Pending"
                            $projectsAffected[$id]= [
                                $projName => [
                                    'project'   => $projName,
                                    'date'      => 'Pending',
                                ]
                            ];
                            $modified = true;
                        }
                        else {
                            //Otherwise, it is not necessary to change
                            $projectsAffected[$id] = [
                                $projName => $data,
                            ];
                        }
                    }
                    break; //We already
                }
                else{
                    // if the information refers to another project, let that information as it was.
                    $projectsAffected[$id] = [
                        $projName => $data,
                    ];
                }
            }
            //If the current RTUchange has not been modified, we can remove it from the list of changes to UPDATE
            if(!$modified){
                unset($projectsAffected[$id]);
            }
            else{
                //Otherwise, this entry needs to be UPDATED, setting the current project to Pending and the other projects
                //unmodified
            }
        }
    }
//    print_r($projectsAffected);
    $ids = array();
    $partialSQL = array();
    foreach ($projectsAffected as $id => $projects){
        $partialSQL[] = "WHEN id='$id' THEN '".json_encode($projects)."'";
        $ids[]=$id;
    }
    $query = "UPDATE firewallUpdates SET projects = CASE ".implode(' ', $partialSQL)." END WHERE id in (".implode(',',$ids).")";
//    echo "$query\n";
    $RTUpdatesDB->query($query);

}