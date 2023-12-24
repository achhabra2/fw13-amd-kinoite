#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Replacing Power Profiles Daemon with Patched Version'

rpm-ostree override replace --experimental --freeze --from repo='copr:copr.fedorainfracloud.org:mariolimonciello:power-profiles-daemon' power-profiles-daemon
