#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Installing Packages'

cp /tmp/config/files/usr/etc/yum.repos.d/1password.repo /etc/yum.repos.d/1password.repo
cp /tmp/config/files/usr/etc/yum.repos.d/brave.repo /etc/yum.repos.d/brave.repo

rpm-ostree install brave-browser 1password
rpm-ostree install https://github.com/Umio-Yasuno/amdgpu_top/releases/download/v0.3.1/amdgpu_top-0.3.1-1.x86_64.rpm