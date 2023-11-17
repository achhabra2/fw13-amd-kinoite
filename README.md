## Custom Kinoite Image for Framework 13 AMD

This is a customized Universal Blue Kinoite Image for the Framework 13 AMD edition. 

### Changes to Kinoite-Main Image
- [11/17] Add Calibrated ICC Profiles
- Add PCIE and USB power saving configurations to /etc/udev/rules.d/
- Add wifi power saving configuration to /etc/sysctl.d/
- Add wifi power saving configuration for intel wifi to /etc/udev/modprobe.d/
- Add AMD s2idle and psr debugging scripts to /usr/share/ublue-os/scripts
- Add udev rules to change AMD EPP Hints on AC Power / Battery
- Add sysctl.d rules for `vm.dirty_writeback_centisecs` and `kernel.nmi_watchdog` parameters for power saving
- Make scripts / kernel parameters available via just script
  - `just fw13-amd` to update default kernel parameters (cpufreq.default_governor=powersave, pcie_aspm.policy=powersupersave)
  - `just check_sleep` to run amd_s2idle.py debug script
  - `just check_psr` to run psr.py debug script
  - `just epp_power` to set AMD EPP Hints to Power Saving
  - `just epp_balance_power` to set AMD EPP Hints to Balance Power
  - `just epp_balance_performance` to set AMD EPP Hints to Balance Performance
  - `just epp_performance` to set AMD EPP Hints to Performance
- Install powertop, kernel-tools, fprintd, fwupd, tailscale, 1password and other apps by default
- Install AMDGPU_TOP by default
- Make some commonly installed Flatpaks available to install on first boot, these are completely optional


### Installing

To install if you are already on Silverblue / Kinoite or an ostree install:

`rpm-ostree rebase ostree-unverified-registry:ghcr.io/achhabra2/fw13-amd-kinoite:latest`

Reboot and then run:

`rpm-ostree rebase ostree-image-signed:docker://ghcr.io/achhabra2/fw13-amd-kinoite:latest`

