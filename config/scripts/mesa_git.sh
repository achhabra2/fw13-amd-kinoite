#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Setting Up Mesa Drivers from Git'

rpm-ostree override replace --experimental --freeze \
    --from repo=copr:copr.fedorainfracloud.org:xxmitsu:mesa-git \
    mesa-filesystem \
    mesa-libxatracker \
    mesa-libglapi \
    mesa-dri-drivers \
    mesa-libgbm \
    mesa-libEGL \
    mesa-vulkan-drivers \
    mesa-libGL

rpm-ostree install mesa-va-drivers

