!include /usr/share/ublue-os/just/100-bling.just

# Include some of your custom scripts here!

# Add boot parameters needed for a Framework 13 AMD laptop
fw-amd:
  #!/usr/bin/env bash
  rpm-ostree kargs --append="amdgpu.sg_display=0"