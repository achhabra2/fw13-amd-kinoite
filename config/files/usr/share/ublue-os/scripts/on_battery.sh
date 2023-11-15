#!/usr/bin/bash

# Change Dirty Writeback Centisecs according to TLP / Powertop
echo '15000' > '/proc/sys/vm/dirty_writeback_centisecs';

# Change AMD Paste EPP energy preference
# Available profiles: performance, balance_performance, balance_power, power
echo 'balance_power' | tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference;

