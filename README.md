# Mininet UDP Traffic Measurement and SDN Flow Analysis

This project measures UDP traffic in a Mininet network and compares application-level results with statistics collected from an OpenFlow switch.

The virtual topology contains two hosts, `h1` and `h2`, connected through an Open vSwitch switch, `s1`, which is managed by an SDN controller. The UDP sender on `h1` sends traffic to a receiver on `h2`. The application records sent and received packets and bytes, while the controller collects switch flow statistics.

The measurements can be used to calculate throughput and packet loss, and to compare what the applications observe with what the network switch counts.

## Files

- `udp_sender.c` — sends UDP traffic.
- `udp_receiver.c` — receives UDP traffic.
- `controller.py` — handles switch events and collects flow statistics.
- `run_controller.py` — starts the SDN controller.

## Requirements

- Linux
- Mininet
- Open vSwitch
- Python 3
- The controller dependencies used by this project

## Usage

Start the controller and Mininet topology using the project’s run instructions. Start the UDP receiver on `h2`, then run the sender on `h1`. After the test, compare the sender and receiver output with the switch flow statistics.

The results depend on the network configuration and test settings, so record the packet size, sending rate, duration, and polling interval for each run.
