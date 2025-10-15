# COMP536: Secure and Cloud Computing

This repository contains assignments for the Rice COMP536 course on Secure and Cloud Computing.

## Repository Structure

- **HW1/**: 
  - **part1/**: Multithreading experiments with `program.c` and interleaving analysis.
  - **part2/**: Performance comparison of `version1.c` and `version2.c` with execution time analysis.
- **HW2/**: 
  - Implementation of P4-based load balancers with ECMP load balancing, per-packet load balancing, and flowlet switching.
  - Includes scripts for generating random flows, querying byte counters, and analyzing packet reordering.

## Key Files

- **HW1/part1/program.c**: Multithreaded program for interleaving analysis.
- **HW1/part2/version1.c & version2.c**: Two versions of a program for performance comparison.
- **HW2/multi_lb.p4**: P4 program implementing the load balancer.
- **HW2/random_flows.py**: Script to generate random flows for testing.
- **HW2/query_bytes.py**: Script to query byte counters from the load balancer.
- **HW2/receive_ooo.py**: Script to analyze out-of-order packet delivery.

## Usage

1. **HW1**:
   - Compile using the provided `Makefile`.
   - Run `program.sh` (part1) or `run.sh` (part2) for experiments.
2. **HW2**:
   - Put the folder under `~/tutorials/exercises`
   - Run `make clean && make run`
   - Run `./receive_ooo.py` on H2
   - Run `./random_flows.py --mode 1` on H1
   - See report (HW2-hc105.pdf) for more details

## Prerequisites

- GCC and `make` for C programs.
- Python 3 with `scapy`.
- P4 development environment - [setup tutorial](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md)