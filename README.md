# Milestone
- 11.4 start
- 11.5 standard AES128 completed
- 11.7 T-table optimization completed
- 12.4 Parallel AES128 completed
- 12.10 Parallel AES128 with shared memory and warp shuffle completed
- 12.11 Experiment
- 12.12 Profile

# Usage

Run `generator.py` to generate test data in the input folder.
Run compile.sh in project root directory to build the project (this will create two exe files: `test` and `profile`)
Run `test` to get results in the output folder.
Use ncu to profile `profile` to get performance data


# BUG
- test.cpp No average by running multiple iterations. Segmentation fault when iterations > 1 (probably memory leak)

# version

$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.5 LTS
Release:        22.04
Codename:       jammy

$ nvidia-smi
Thu Dec 12 05:47:54 2024       
+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 560.35.05              Driver Version: 560.35.05      CUDA Version: 12.6     |
|-----------------------------------------+------------------------+----------------------+
| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |
|                                         |                        |               MIG M. |
|=========================================+========================+======================|
|   0  NVIDIA L4                      Off |   00000000:00:03.0 Off |                    0 |
| N/A   54C    P8             18W /   72W |     130MiB /  23034MiB |      0%      Default |
|                                         |                        |                  N/A |
+-----------------------------------------+------------------------+----------------------+

$ g++ --version
g++ (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

$ python --version
Python 3.10.12