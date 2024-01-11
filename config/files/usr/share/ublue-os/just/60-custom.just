import /usr/share/ublue-os/just/100-bling.just

# Include some of your custom scripts here!

# Add boot parameters needed for a Framework 13 AMD laptop
fw13-amd:
  #!/usr/bin/env bash
  echo 'Adding Recommended Kernel Parameters for Framework 13 AMD'
  rpm-ostree kargs --append="cpufreq.default_governor=powersave" --append="pcie_aspm.policy=powersupersave" --append="amd_pstate=active"

# Run amd s2idle script for debugging sleep issues
check_sleep:
  #!/usr/bin/env bash
  echo 'Running amd_s2idle.py'
  sudo /usr/bin/python3 /usr/share/ublue-os/scripts/amd_s2idle.py

# Run amd psr script for debugging psr issues
check_psr:
  #!/usr/bin/env bash
  echo 'Running psr.py'
  sudo /usr/bin/python3 /usr/share/ublue-os/scripts/psr.py

# Set EPP to power saving mode
epp_power:
  echo 'power' | sudo tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference

# Set EPP to balance power mode
epp_balance_power:
  echo 'balance_power' | sudo tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference

# Set EPP to balance performance mode
epp_balance_performance:
  echo 'balance_performance' | sudo tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference

# Set EPP to performance mode
epp_performance:
  echo 'performance' | sudo tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference

