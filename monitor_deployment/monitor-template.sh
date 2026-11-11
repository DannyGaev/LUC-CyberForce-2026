#!/bin/bash
# From https://oneuptime.com/blog/post/2026-01-15-use-inotifywait-file-monitoring-ubuntu/view

# Configuration
aiqsndn=()


# SSH
anmskdfbnui() {
    local line="$1"
    # Using tail to get recent entries
    hfbdsjl=$(grep "Starting session:" <<< "$line" | awk '{print $12}')
    echo "${aiqsndn[@]}" | grep -q "$hfbdsjl"
    if [  $? -ne 0 ]; then
        nnkjasodh "$line"
        echo "bad"
    fi
}

# Function to send alerts
nnkjasodh() {
    local udgfsaois="$1"
    local asdjnasdjnw=$(echo "$udgfsaois" | awk -F'from' '{print $2}' | awk '{print $1}')
    local iwnboasdnos=$(echo "$udgfsaois" | awk -F'for' '{print $2}' | awk '{print $1}')
    local isuqnbndia
    isuqnbndia=$(date '+%Y-%m-%d %H:%M:%S')

    # https://gist.github.com/AdamDWalker/a895ecae0a77fe7f679cb7a7254a179b
    hudslnc="Unknown IP address $asdjnasdjnw succesfully authenticated as $iwnboasdnos at $isuqnbndia"
    nbasusdff=\"$hudslnc\"
    nasjsuqgham=""
    curl -H "Content-Type: application/json" -X POST -d "{\"content\": $nbasusdff}" $nasjsuqgham
}

# Monitor log files for modifications
inotifywait -m -e modify --format '%w%f' /var/log/auth.log | while read -r modified_file; do
      last_line=$(tail -n 1 "$modified_file")
      anmskdfbnui "$last_line"
done