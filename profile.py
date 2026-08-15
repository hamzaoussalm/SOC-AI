"""
SOC-AI CloudLab Profile

Instructions:
This profile creates the initial infrastructure for an AI-based
network intrusion detection system.

Topology:
ATTACKER <-> SENSOR <-> TARGET
                    |
                    +-> ML
                    +-> DASHBOARD
"""

import geni.portal as portal
import geni.rspec.pg as rspec


request = portal.context.makeRequestRSpec()

# ============================================================
# NODES
# ============================================================

attacker = request.XenVM("attacker")
sensor = request.XenVM("sensor")
target = request.XenVM("target")
ml = request.XenVM("ml")
dashboard = request.XenVM("dashboard")


# ============================================================
# NETWORK INTERFACES
# ============================================================

# Attacker <-> Sensor
attacker_if = attacker.addInterface("attacker-data")
sensor_attacker_if = sensor.addInterface("sensor-attacker")

attacker_if.addAddress(
    rspec.IPv4Address("10.10.1.10", "255.255.255.0")
)

sensor_attacker_if.addAddress(
    rspec.IPv4Address("10.10.1.1", "255.255.255.0")
)


# Sensor <-> Target
sensor_target_if = sensor.addInterface("sensor-target")
target_if = target.addInterface("target-data")

sensor_target_if.addAddress(
    rspec.IPv4Address("10.10.2.1", "255.255.255.0")
)

target_if.addAddress(
    rspec.IPv4Address("10.10.2.10", "255.255.255.0")
)


# Management network
sensor_mgmt_if = sensor.addInterface("sensor-mgmt")
ml_mgmt_if = ml.addInterface("ml-mgmt")
dashboard_mgmt_if = dashboard.addInterface("dashboard-mgmt")

sensor_mgmt_if.addAddress(
    rspec.IPv4Address("10.10.3.1", "255.255.255.0")
)

ml_mgmt_if.addAddress(
    rspec.IPv4Address("10.10.3.10", "255.255.255.0")
)

dashboard_mgmt_if.addAddress(
    rspec.IPv4Address("10.10.3.20", "255.255.255.0")
)


# ============================================================
# LINKS
# ============================================================

attack_link = request.LAN("attack-network")
attack_link.addInterface(attacker_if)
attack_link.addInterface(sensor_attacker_if)


target_link = request.LAN("target-network")
target_link.addInterface(sensor_target_if)
target_link.addInterface(target_if)


management_link = request.LAN("management-network")
management_link.addInterface(sensor_mgmt_if)
management_link.addInterface(ml_mgmt_if)
management_link.addInterface(dashboard_mgmt_if)


# ============================================================
# OUTPUT
# ============================================================

portal.context.printRequestRSpec()
