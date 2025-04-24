#!/bin/bash

# Script to upload compiled rustp2p test executable and library to the server.

# --- Configuration ---
KEY_FILE="/root/sshkey.pem"
REMOTE_USER="root"
REMOTE_HOST="121.41.107.198"
REMOTE_DIR="/root/p2p_test" # IMPORTANT: This directory must exist on the server!

LOCAL_BIN="examples/c_examples/build/tcp_test"
LOCAL_LIB="target/release/librustp2p.so"
# --- End Configuration ---

# --- Pre-checks ---
echo "Checking local files..."
if [ ! -f "$LOCAL_BIN" ]; then
    echo "Error: Local executable not found at $LOCAL_BIN"
    echo "Did you run the build script (./build-x64.sh)?"
    exit 1
fi
if [ ! -f "$LOCAL_LIB" ]; then
    echo "Error: Local library not found at $LOCAL_LIB"
    echo "Did you run the build script (./build-x64.sh)?"
    exit 1
fi
echo "Local files found."

echo "Checking SSH key permissions..."
# Get permissions as octal number, suppress error if key doesn't exist
perms=$(stat -c "%a" "$KEY_FILE" 2>/dev/null)
if [ -z "$perms" ]; then
    echo "Warning: Key file $KEY_FILE not found or inaccessible."
elif [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
    echo "Warning: Key file $KEY_FILE has permissions $perms. SSH might reject it."
    echo "Consider running: chmod 600 $KEY_FILE"
fi

# --- Uploading ---
echo "Uploading $LOCAL_BIN to $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR ..."
scp -i "$KEY_FILE" "$LOCAL_BIN" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to upload $LOCAL_BIN."
    exit 1
fi
echo "$LOCAL_BIN uploaded successfully."

echo "Uploading $LOCAL_LIB to $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR ..."
scp -i "$KEY_FILE" "$LOCAL_LIB" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to upload $LOCAL_LIB."
    exit 1
fi
echo "$LOCAL_LIB uploaded successfully."

echo "--- Upload complete! ---"
echo "Remember to set LD_LIBRARY_PATH on the server if needed:"
echo "export LD_LIBRARY_PATH=\"${REMOTE_DIR}:\$LD_LIBRARY_PATH\""

exit 0 