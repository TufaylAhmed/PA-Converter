#!/bin/bash

function getNumberQuestion {
    question=$1
    recommendationText=$2
    recommendationValue=$3

    valid=0
    while [ $valid -lt 1 ]
        do
        echo ${question}?
        read -p 'Modify [Y/n]: ' modifyOption
        if [ "$modifyOption" == "Y"  -o "$modifyOption" == "" ]; then
            modifyOption="Y"
            valid=1;
        elif [ "$modifyOption" == "n" ]; then
            myresult=-1;
            valid=1;
        fi
        done

    if [ "$modifyOption" == "Y" ]; then
        valid=0
        while [ $valid -lt 1 ]
            do
            echo ${recommendationText}?
            read -p "New Value [${recommendationValue}]: " myresult;
            re='^[0-9]+$'
            if [[ $myresult =~ $re ]]; then
                valid=1;
            elif [ "$myresult" == "" ]; then
                myresult=32;
                valid=1;
            fi
            done
    fi
}


PATH=/etc/mysql/

getNumberQuestion "Do you want to modify Max_Allowed_Packet for MySQL/MariaDB?" "Specify Max_allowed_packet (min. 32MB recommended)" 32
echo $myresult
a=64
# Find files that have config information
if [ $myresult -gt 16 ]; then
    cd ${PATH}
    /usr/bin/find ./ -type f -exec /bin/sed -i "s/max_allowed_packet/max_allowed_packet =   ${myresult}M      # old value: max_allowed_packet/" {} \;
fi
#     egrep -R "max_allowed_packet" 2>/dev/null | awk '{print $1}' | awk -F ":" '{print $1}'
