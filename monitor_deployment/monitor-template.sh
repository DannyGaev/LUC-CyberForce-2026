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
    elif [[ $line == *"wget"* ]]; then
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
        hudslnc="Unknown IP address $asdjnasdjnw succesfully authenticated as $iwnboasdnos at $isuqnbndia"
    elif [[ $line == *"wget"* ]]; then
        # "id" of exec chain
        nasksuwh=$(grep "wget_usage" <<< "$line" | awk '{print $2}' | awk -F"audit" '{print $2}' | awk -F'):' '{print $1}' | awk -F'(' '{print $2}')

        # path
        basyhdjao=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F'exe=' '{print $2}' | awk '{print $1}' | tr -d '"')

        #auid of user
        nusdnsal=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F'auid=' '{print $2}' | awk '{print $1}')

        #uid of user
        nufjdisf=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "SYSCALL" | awk -F' uid=' '{print $2}' | awk '{print $1}')

        # directory of exection
        naisydbo=$(tail -n 10 /var/log/audit/audit.log | grep "$nasksuwh" | grep "CWD" | awk -F'cwd=' '{print $2}' | awk -F'"' '{print $2}')
        
        hudslnc="User with auid $nusdnsal and uid $nufjdisf executed the command $basyhdjao in the directory $naisydbo at $isuqnbndia"
    fi
    nbasusdff=\"$hudslnc\"
    nasjsuqgham=""
    curl -H "Content-Type: application/json" -X POST -d "{\"content\": $nbasusdff}" $nasjsuqgham
}

# Monitor log files for modifications
inotifywait -m -e modify --format '%w%f' /var/log/auth.log /var/log/audit/audit.log | while read -r modified_file; do
      last_line=$(tail -n 1 "$modified_file")
      anmskdfbnui "$last_line"
done