#!/usr/bin/bash

# Change Dirty Writeback Centisecs according to TLP / Powertop
echo '1500' > '/proc/sys/vm/dirty_writeback_centisecs';

# Set PPD on Unplug, user can always manually override
powerprofilesctl set power-saver

# Change AMD Paste EPP energy preference
# Available profiles: performance, balance_performance, balance_power, power
# echo 'balance_power' | tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference;

echo 'powersupersave' | tee /sys/module/pcie_aspm/parameters/policy