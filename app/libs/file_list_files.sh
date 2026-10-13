#!/bin/bash

directory=$1
output_file=$2

echo $directory;
echo $output_file;

echo "[" > "$output_file"

isFirst=1
while IFS= read -r -d $'\0' file; do
    filename=$(basename "$file")
    if [[ $filename =~ \.(log|csv|csv\.gz)$ ]]; then
        if [[ $isFirst -eq 0 ]]; then
            echo "," >> "$output_file"
        fi
        isFirst=0

        path=$(dirname "$file")
        name=$(basename "$file")
        date=$(stat -c %y "$file" | awk '{print $1}')
        echo "{" >> "$output_file"
        #echo '  "path": "'"$path"'",' >> "$output_file"
        echo '  "name": "'"$path/$name"'",' >> "$output_file"
        echo '  "date": "'"$date"'"' >> "$output_file"
        echo "}" >> "$output_file"
    fi
done < <(find "$directory" -type f -print0)

echo "]" >> "$output_file"