<?php

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';

class AfterProcessCSV
{
    /* @var mysqli */
    private $pandbRBAC;

    public function __construct()
    {
        $this->pandbRBAC = selectDatabase("pandbRBAC");
    }

    public function deleteFiles(array $logPathsToDelete)
    {
        foreach ($logPathsToDelete as $path) {
            $query = "SELECT * FROM processedLogs WHERE message like '%$path%' AND status='processed'";
            $results = $this->pandbRBAC->query($query);
            if ($results->num_rows > 0) {
                if(file_exists($path)) {
                    unlink($path);
                    //exec("rm $path");
                }
            }
        }
    }

    public function compressFiles(array $logPathsToCompress)
    {
        foreach ($logPathsToCompress as $path) {
            $path = $this->pandbRBAC->real_escape_string($path);
            $query = "SELECT * FROM processedLogs WHERE message like '%$path%' AND status='processed'";
            $results = $this->pandbRBAC->query($query);
            if ($results->num_rows > 0) {
                if(file_exists($path)) {
                    exec("gzip " . escapeshellarg($path));
                }
            }

        }
    }

}

if(isset($argv))
{
    $afterProcessActionsFile = $argv[1];
    if(!$content =  file_get_contents($afterProcessActionsFile)){
        return;
    }
    $clean = str_replace("}", "", str_replace("{", "", $content));
    $argv = explode(";", $clean);

    foreach ($argv as $arg) {
        $tupla = explode(':', $arg);
        $tupla[0] = str_replace('"', '', $tupla[0]);
        $tupla[1] = str_replace('"', '', $tupla[1]);
        switch ($tupla[0]) {
            case "deletePaths":
                /* @var String[] */
                $deletePaths = explode(",",$tupla[1]);
                break;
            case "zipPaths":
                /* @var String[] */
                $zipPaths = explode(",",$tupla[1]);
                break;

            default:
                break;
        }
    }

    $a = new AfterProcessCSV();

    $deletePaths = array_filter($deletePaths);
    if(isset($deletePaths)){
        $a->deleteFiles($deletePaths);
    }

    $zipPaths = array_filter($zipPaths);
    if(isset($zipPaths)){
        $a->compressFiles($zipPaths);
    }

}

