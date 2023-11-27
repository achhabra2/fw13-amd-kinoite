#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Installing Patched Power Profiles Daemon'

git clone https://gitlab.freedesktop.org/xdbob/power-profiles-daemon.git

cd power-profiles-daemon
git checkout -b multi-drivers

meson _build -Dprefix=/usr
ninja -v -C _build install