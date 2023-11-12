!include /usr/share/ublue-os/just/100-bling.just

# Include some of your custom scripts here!

# Add boot parameters needed for a Framework 13 AMD laptop
fw-amd:
  #!/usr/bin/env bash
  echo 'Adding Recommended Kernel Parameters for Framework 13 AMD'
  echo 'Setting amdgpu.sg_display=0, amd_iommu=off, amd_pstate=guided'
  rpm-ostree kargs --append="amdgpu.sg_display=0" --append="amd_iommu=off" --append="amd_pstate=guided"

check_sleep:
  #!/usr/bin/env bash
  echo 'Running amd_s2idle.py'
  /usr/bin/python3 /usr/share/ublue-os/scripts/amd_s2idle.py

check_psr:
  #!/usr/bin/env bash
  echo 'Running psr.py'
  /usr/bin/python3 /usr/share/ublue-os/scripts/psr.py