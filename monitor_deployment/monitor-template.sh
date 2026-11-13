#!/bin/bash
# From https://oneuptime.com/blog/post/2026-01-15-use-inotifywait-file-monitoring-ubuntu/view

# Configuration
aiqsndn=()

# SSH
anmskdfbnui() {
    local line="$1"
    if [[ $line == *"Starting session"* ]]; then
        hfbdsjl=$(grep "Starting session:" <<< "$line" | awk '{print $12}')
        echo "${aiqsndn[@]}" | grep -q "$hfbdsjl"
        if [  $? -ne 0 ]; then
            nnkjasodh "$line"
        fi
    elif [[ $line == *"PROCTITLE"* ]]; then
        nnkjasodh "$line"
    fi
}

# Function to send alerts
nnkjasodh() {
    local udgfsaois="$1"
    isuqnbndia=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ $udgfsaois == *"Starting session"* ]]; then
        asdjnasdjnw=$(echo "$udgfsaois" | awk -F'from' '{print $2}' | awk '{print $1}')
        iwnboasdnos=$(echo "$udgfsaois" | awk -F'for' '{print $2}' | awk '{print $1}')

        # https://gist.github.com/AdamDWalker/a895ecae0a77fe7f679cb7a7254a179b
        hudslnc="**=======[Suspicious Login]=======**\nUnknown IP address $asdjnasdjnw succesfully authenticated as $iwnboasdnos at $isuqnbndia\n--------------------------------------------"
                
    elif [[ $line == *"PROCTITLE"* ]]; then
        # "id" of exec chain
        nasksuwh=$(grep "PROCTITLE" <<< "$line" | awk '{print $2}' | awk -F"audit" '{print $2}' | awk -F'):' '{print $1}' | awk -F'(' '{print $2}')

        # full execve
        masiqowll=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "EXECVE")
        najsdlask="${masiqowll//\"/\\\"}"
        # path
        basyhdjao=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F'exe=' '{print $2}' | awk '{print $1}' | tr -d '"')

        #auid of user
        nusdnsal=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F'auid=' '{print $2}' | awk '{print $1}')

        #uid of user
        nufjdisf=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F' uid=' '{print $2}' | awk '{print $1}')

        # directory of exection
        naisydbo=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "CWD" | awk -F'cwd=' '{print $2}' | awk -F'"' '{print $2}')
        if [[ "$nusdnsal" != "4294967295" && -n "$nusdnsal" ]]; then
                hudslnc="**=======[Suspicious Binary Execution]=======**\nUser with auid $nusdnsal and uid $nufjdisf executed the command $basyhdjao in the directory $naisydbo at $isuqnbndia.\n\nFull EXECVE is: '$najsdlask'\n------------------------------------------------"
        else
                hudslnc="NAN"
        fi
    fi
    if [[ "$hudslnc" != "NAN" ]]; then
        nbasusdff=\"$hudslnc\"
        nasjsuqgham=""
        curl -H "Content-Type: application/json" -X POST -d "{\"content\": $nbasusdff}" $nasjsuqgham
    fi
}

# Monitor log files for modifications
inotifywait -m -e modify --format '%w%f' /var/log/auth.log /var/log/audit/audit.log | while read -r modified_file; do
      last_line=$(tail -n 1 "$modified_file")
      anmskdfbnui "$last_line"
done