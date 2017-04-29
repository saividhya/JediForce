#!/bin/bash
file=$1
# Handle non-absolute paths
if ! [[ "$file" == /* ]] ; then
    path=.
fi
dirname "$file" | tr '/' $'\n' | while read part ; do
    path="$path/$part"
    # Check for execute permissions
    if ! [[ -x "$path" ]] ; then
        echo "'$path' is blocking access."
    fi
done
if ! [[ -r "$file" ]] ; then
    echo "'$file' is not readable."
fi
#/*reference https://unix.stackexchange.com/questions/82347/how-to-check-if-a-user-can-access-a-given-file
#To check this for a specific user, you can use sudo.
#sudo -u joe ./check-permissions.sh /long/path/to/file.txt
#*/
