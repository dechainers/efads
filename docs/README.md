# Introduction

![EFADS Logo](logo.png)

Welcome to the official EFADS documentation page.

If you want to consult the API doc, visit [this](api/) page.

## Components

There are 4 main components placed in different part of the system that interacts with each other:

1. **TrafficAnalyser**: responsible for applying the monitoring logic to the network traffic, choosing whether to take a packet into account, discard it because it's blacklisted, or ignore it due to not enoguh space. It collects features concerning the analysed packets, and forward such data to the DetectioEngine when a time window finishes.
2. **DetectioEngine**: the component running the neural network. It receives input data from the traffic analyser, it classifies the traffic and gives the result of the prediction to the policy enforcer.
3. **PolicyEnforcer**: the component that, given the result of the traffic classification, applies policies to the network traffic (e.g., block all traffic from a suspicious session).
4. **AnalisysAdjuster**: the component that, given the state of the system and of the previous classified sessions, decides whether to adjust the granularity and type of monitoring logic. It computes also statistics concerning the classifications.

## Simulated Operational Mode

This mode works completely outside the DeChainy framework and has been developed to perform simulations with traffic captures. All the interactions between components are simulated, no actual programs are injected in the system.

## Live Operational Modes

While the DetectionEngine, PolicyEnforcer and AnalysisAdjuster are three components fully running in userspace, the TrafficAnalyser may be composed by different modules running on different area of the OS, which are dependent by the operational mode.

For this types of test, a Linux kernel version >= 5.6 is required.

### Full-eBPF

```bash
 ------------------------------------------
|                VICTIM NODE               |
|        -------------------------         |
|       |            OS            |       |
|       |       (user space)       |       |
|       |        -----------       |       |
|       |       | extractor |      |       |
|       |        -----------       |       |
|       |             +            |       |
|        -------------|------------        | 
|  -------------------|------------------  |
| |                  NIC                 | |
| |            (kernel space)            | |
| |  ----------- ---------- -----------  | |
| | | mitigator | analyser | collector | | |
| |  ----------- ---------- -----------  | |
| |                   +                  | |
|  -------------------|------------------  |
 --------------------|||-------------------
```

The TrafficAnalyser is composed by:

1. **mitigator**: an eBPF program running in kernel space containing the blacklistes sessions.
2. **analyser**: an eBPF program that uses support structure maps to check whether the monitoring logic has to be applied to the network packets. Accepted packets are then stored in the **collector**
3. **collector**: an eBPF swappable map deployed in kernel space, accessible also from user space using apposite system calls, which collects the result of the analysis.
4. **extractor**: a user space module that extract data from eBPF programs and forwards it to the further components (DetectionEngine, etc.)

Pros:

* high-speed network traffic processing thanks to
  * monitoring actions in kernel, no additional system delay (system calls or whatever)
  * extracted only needed information from packets
* adaptiveness, programs can be recompiled/patched/upgraded at runtime

Cons:

* limited space in kernel for
  * instructions
  * data structures

### Filtered-eBPF

```bash
 ------------------------------------------
|               VICTIM NODE                |
|  --------------------------------------  |
| |                  OS                  | |
| |             (user space)             | |
| |       ----------- -----------        | |
| |      | collector | extractor |       | |
| |       ----------- -----------        | |
| |                  +                   | |
|  ------------------|-------------------  | 
|       -------------|------------         |
|      |            NIC           |        |
|      |       (kernel space)     |        |
|      |  ----------- ----------  |        |
|      | | mitigator | analyser | |        |
|      |  ----------- ----------  |        |
|      |             +            |        |
|       -------------|------------         |
 -------------------|||--------------------
```

The TrafficAnalyser is composed by:

1. **mitigator**: an eBPF program running in kernel space containing the blacklistes sessions.
2. **analyser**: an eBPF program that uses support structure maps to check whether the monitoring logic has to be applied to the network packets. It forwards accepted packets to the **collector** in the user space via *perf_buffer* events.
3. **collector**: a userspace thread that stores the forwarded event into apposite data structure already formatted.
4. **extractor**: a user space thread that forwards gathered data to the further components without further ado (DetectionEngine, etc.)

Pros:

* medium/high-speed network traffic processing thanks to
  * monitoring actions partially in kernel, only the filtering section
  * extracted only needed information from packets
* adaptiveness, programs can be recompiled/patched/upgraded at runtime

Cons:

* limited monitored data
  * number of events forwarde to user space must be low, otherwise possible lost samples

### Socket

```bash
 -----------------------------------------------------
|                     VICTIM NODE                     |
|  -------------------------------------------------  |
| |                        OS                       | |
| |                   (user space)                  | |
| |         ---------- ----------- -----------      | |
| |        | analyser | collector | extractor |     | |
| |         ---------- ----------- -----------      | |
| |                        +                        | |
|  ------------------------|------------------------  |
|                   -------|-------                   |
|                  |      NIC      |                  |
|                  |(kernel space) |                  |
|                  |  -----------  |                  |
|                  | | mitigator | |                  |
|                  |  -----------  |                  |
|                  |       +       |                  |
|                   -------|-------                   |
 -------------------------|||-------------------------
```

The TrafficAnalyser is composed by:

1. **mitigator**: an eBPF program running in kernel space containing the blacklistes sessions.
2. **analyser**: a user space program that analyses the network traffic
3. **collector**: a user space data structure within the analyser where all the data is stored.
4. **extractor**: a user space thread within the analyser that forwards data to the further components (DetectionEngine, etc.).

Pros:

* all-in-place solution
  * components are easily deployed in the same space
* no strick OS requirements

Cons:

* offline and low-speed network monitoring
  * packets are copied to the user space program
  * user space routines are slower than kernel space analysis
* no adaptiveness
