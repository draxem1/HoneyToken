#!/bin/bash

# Create session hash.
HASH=$(openssl rand -hex 12)

# Check if hash exist traversing dir
# Use if not, otherwise generate new
for file in *; do
    if [[ -f "$file" ]]; then
        if [[ "$file" == "$HASH.txt" ]]; then
            HASH=$(openssl rand -hex 12)
        fi
    fi
done

script --timing="$HASH.tm" "$HASH.log"
