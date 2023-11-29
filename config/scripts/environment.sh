#!/usr/bin/env bash

# Tell this script to exit if there are any errors.
# You should have this in every custom script, to ensure that your completed
# builds actually ran successfully without any errors!
set -oue pipefail

# Your code goes here.
echo 'Setting Environment Variable for ROCM'

echo 'export HSA_OVERRIDE_GFX_VERSION=11.0.0' >> /usr/etc/profile.d/hsa_override.sh
