## Custom Kinoite Image for Framework 13 AMD

This is a customized Universal Blue Kinoite Image for the Framework 13 AMD edition. 

### Changes to Kinoite-Main Image
- Add PCIE and USB power saving configurations to /etc/udev/rules.d/
- Add wifi power saving configuration to /etc/sysctl.d/
- Add wifi power saving configuration for intel wifi to /etc/udev/modprobe.d/
- Add AMD s2idle and psr debugging scripts to /usr/share/ublue-os/scripts
- Make scripts / kernel parameters available via just script
  - `just fw-amd` to update default kernel parameters (amdgpu.sg_display=0, amd_iommu=off, amd_pstate=guided)
  - `just check_sleep` to run amd_s2idle.py debug script
  - `just check_psr` to run psr.py debug script
- Install powertop, fprintd, fwupd, tailscale, 1password and other apps by default
- Install AMDGPU_TOP by default
- Make some commonly installed Flatpaks available to install on first boot, these are optional