#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Setting Script Permissions'

chmod +x /usr/share/ublue-os/scripts/on_ac.sh
chmod +x /usr/share/ublue-os/scripts/on_battery.sh