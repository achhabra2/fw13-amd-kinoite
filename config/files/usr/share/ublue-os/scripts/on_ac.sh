#!/usr/bin/bash

# Change Dirty Writeback Centisecs according to TLP / Powertop
echo '500' > '/proc/sys/vm/dirty_writeback_centisecs';

# Change AMD Paste EPP energy preference
# Available profiles: performance, balance_performance, balance_power, power
echo 'balance_performance' | tee /sys/devices/system/cpu/cpufreq/policy*/energy_performance_preference;

