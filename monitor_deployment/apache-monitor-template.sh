#!/bin/bash
# From https://oneuptime.com/blog/post/2026-01-15-use-inotifywait-file-monitoring-ubuntu/view

# Configuration
aiqsndn=()
# flags=("wp-upload-helper.php" "wp-upgrade-helper.php" "wp-cache-index.php")   formerly used for early detection of attacks

check_for_alerts() {
    local line="$1"
    send_alert "$line"
}

send_alert() {
    local udgfsaois="$1"
    local asdjnasdjnw=$(echo "$udgfsaois" | awk '{print $1}')
    local iwnboasdnos=$(echo "$udgfsaois" | awk '{print $6}' | tr -d '"')
    local jsdfyewllwe=$(echo "$udgfsaois" | awk '{print $7}')
    local isuqnbndia=$(date '+%Y-%m-%d %H:%M:%S')

    # https://gist.github.com/AdamDWalker/a895ecae0a77fe7f679cb7a7254a179b
    hudslnc="IP address $asdjnasdjnw sent a $iwnboasdnos request to the endpoint $jsdfyewllwe at $isuqnbndia"
    nbasusdff=\"$hudslnc\"
    nasjsuqgham="https://discord.com/api/webhooks/1570170227533287444/v5zqrSnUzXAtJRV7GPsUdOQ1b9NrAL5qC5y0kzzvjQkTW0A3gD5eFXvqQd91NfOqt3rb"
    TITLE="Early Warning: Website"
    COLOR=$((16#F56547))
    curl -H "Content-Type: application/json" \
     -X POST \
     -d "{
       \"embeds\": [{
         \"title\": \"$TITLE\",
         \"description\": \"$hudslnc\",
         \"color\": $COLOR
       }]
     }" \
     "$nasjsuqgham"
}

# Monitor log files for modifications
inotifywait -m -e modify --format '%w%f' /var/log/apache2/wordpress_access.log | while read -r modified_file; do
      last_line=$(tail -n 1 "$modified_file")
      check_for_alerts "$last_line"
done