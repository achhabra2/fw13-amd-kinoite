#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Updating to latest linux-firmware from git'

git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git

cp -rf linux-firmware/* /usr/lib/firmware/