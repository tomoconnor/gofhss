#!/bin/bash
# test_client.sh
# This script calls the client every 10 seconds with an incrementing counter in the message.
# It checks that the response echoes the sent message.

counter=1

while true; do
  message="Test Message #$counter"
  # The server responds with "Echo: <message>"
  expected="Echo: $message"
  
  echo "--------------------------------------------"
  echo "$(date): Running client test with message: '$message'..."
  
  # Run the client with desired flags. Adjust -robust, -timestamp, and -challenge as needed.
  OUTPUT=$(go run main.go -mode=client -msg "$message" -robust=true -timestamp=true -challenge=true 2>&1)
  
  echo "$OUTPUT"
  
  # Check if the expected response string appears in the output.
  if echo "$OUTPUT" | grep -q "$expected"; then
    echo "$(date): Success - Received expected response: '$expected'"
  else
    echo "$(date): Failure - Expected '$expected' but did not find it in the output."
    echo "$(date): Full output:"
    echo "$OUTPUT"
    
    # Try to extract the actual response for debugging
    actual_response=$(echo "$OUTPUT" | grep "Received response:")
    if [ -n "$actual_response" ]; then
      echo "$(date): Actual response: $actual_response"
    fi
  fi
  
  ((counter++))
  sleep 10
done
