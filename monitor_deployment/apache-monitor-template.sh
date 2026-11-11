#!/bin/bash
# From https://oneuptime.com/blog/post/2026-01-15-use-inotifywait-file-monitoring-ubuntu/view

# Configuration
aiqsndn=()
flags=('wp-upload-helper.php' 'wp-upgrade-helper.php' 'wp-cache-index.php')

check_for_alerts() {
    local line="$1"
    # Using tail to get recent entries

    for flag in ${flags[@]}
    do
        hfbdsjl=$(grep '$flag' <<< "$line" | awk '{print $1}')
        echo "${aiqsndn[@]}" | grep -q "$hfbdsjl"
        if [  $? -ne 0 ]; then
            send_alert "$line"
        fi
    done
}

send_alert() {
    local udgfsaois="$1"
    local asdjnasdjnw=$(echo "$udgfsaois" | awk '{print $1}')
    local iwnboasdnos=$(echo "$udgfsaois" | awk '{print $6}' | tr -d '"')
    local jsdfyewllwe=$(echo "$udgfsaois" | awk '{print $7}')
    local isuqnbndia=$(date '+%Y-%m-%d %H:%M:%S')

    # https://gist.github.com/AdamDWalker/a895ecae0a77fe7f679cb7a7254a179b
    hudslnc="IP address $asdjnasdjnw sent a $iwnboasdnos request to flagged endpoint $jsdfyewllwe at $isuqnbndia"
    nbasusdff=\"$hudslnc\"
    nasjsuqgham=""
    curl -H "Content-Type: application/json" -X POST -d "{\"content\": $nbasusdff}" $nasjsuqgham
}

# Monitor log files for modifications
inotifywait -m -e modify --format '%w%f' /var/log/apache2/wordpress_access.log | while read -r modified_file; do
      last_line=$(tail -n 1 "$modified_file")
      check_for_alerts "$last_line"
done