#!/bin/bash



# Configure variables
declare_variables() {
    user=$(echo $USER)
    sourcePath=/PALogs/PaloAltoSC2
    TrafficRotatorPath=/var/www/html/OS/trafficRotator/prepareTrafficLog.sh
    deviceDeclarationPath=/var/www/html/OS/trafficRotator/devices.txt

    bold=$(tput bold)
    normal=$(tput sgr0)
    RED=$(tput setaf 1)
    BLUE=$(tput setaf 6)
}



# Checking if a folder is writable by the given user
# $1 user
# $2 path
checkWritable(){
    # Check that the destination folder exists
    if [ -d "$2" ]; then
        # Use -L to get information about the target of a symlink,
        # not the link itself, as pointed out in the comments
        INFO=( $(stat -L -c "%a %G %U" $2) )
        PERM=${INFO[0]}
        GROUP=${INFO[1]}
        OWNER=${INFO[2]}

        ACCESS=no
        if (( ($PERM & 0002) != 0 )); then
            # Everyone has write access
            ACCESS=yes
        elif (( ($PERM & 0020) != 0 )); then
            # Some group has write access.
            # Is user in that group?
            gs=( $(groups $1) )
            for g in "${gs[@]}"; do
                if [[ $GROUP == $g ]]; then
                    ACCESS=yes
                    break
                fi
            done
        elif (( ($PERM & 0200) != 0 )); then
            # The owner has write access.
            # Does the user own the file?
            [[ $1 == $OWNER ]] && ACCESS=yes
        fi
    else
        ACCESS=no
    fi

    echo $ACCESS
}



# Param1 Source file path
# Param2 Destination file path
moveFile(){
    isWritable=$(checkWritable $user $2)
    echo "MOVE to desintation"
    echo     "         Checking destination writable? ${bold}$isWritable${normal}"
    if [ $isWritable == "yes" ] ; then
        echo "         Moving ${bold}$1${normal} to the new destination $2"
        mv $1 $2
    else
        echo "         ${RED}Not possible to move $1 to new destination $2${normal}"
    fi
}



# Calls the script to place the headers.
# $1 is the input file
# $2 is the PANOS version for the NGFW that generated the file
placeHeader(){
    echo "Placing the HEADERS in $i for version $2"
    $TrafficRotatorPath -i $1 -V $2
}



# Places the header and moves the file into its final path for processing into parquet
# $1 is the filepath
# $2 is the PANOS version
# $3 is the final destination of the prepared file
processFile(){
    # placeHeader $1 $2 #Not required anymore. The PHP Script can identify the version based on the first and last lines of the file
    echo ""
    moveFile $1 $3
}


#1 device to check
getFilesToProcess(){
    today=`date +%Y_%m_%d`
    files=$(ls "${sourcePath}" | grep "$1_" | grep -v $today )
    echo $files
}



# Establish run order
main() {
    declare_variables
    now=$(date)
    echo
    echo "$now:     Starting log rotation"
    # Loading user settings for each device
    while IFS='' read -r line || [[ -n "$line" ]]; do
        echo "------------------------------------------------------"
        echo "Checking files from: "
        echo "    Original_Line     ${bold}$line${normal}"
        while IFS=',' read -ra ADDR; do
            count=0
            for i in "${ADDR[@]}"; do
                if [ $count -eq 0 ]; then
                    deviceName=$i
                elif [ $count -eq 1 ]; then
                    deviceVersion=$i
                elif [ $count -eq 2 ]; then
                    devicePath="$i"
                fi

                count=$((count + 1))
            done
            echo "    DeviceName        $deviceName"
            echo "    Version           $deviceVersion"
            echo "    Destination_Path  $devicePath"
            echo
        done <<< "$line"

        files=$(getFilesToProcess $deviceName)
        #echo "This are the files $files"
        for file in $files; do
            echo "- - - - - - - - - - - - - - - - - - - - - -"
            echo "File: ${bold}$sourcePath/$file${normal}"
            processFile $sourcePath/$file $deviceVersion $devicePath
            echo "- - - - - - - - - - - - - - - - - - - - - -"
        done
        echo "------------------------------------------------------"

    done < "$deviceDeclarationPath"
    now=$(date)
    echo "$now:     Log Rotation completed"
    echo
}

main