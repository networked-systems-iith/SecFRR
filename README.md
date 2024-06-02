# Anomaly Detection in In-Network Fast ReRoute Systems

## Overview
This repository contains code and resources related to our paper titled "Anomaly Detection in In-Network Fast ReRoute Systems" We propose a novel mechanism to detect malicious traffic patterns targeting fast reroute systems, which can compromise network performance and lead to degradation. 

<img src="https://github.com/networked-systems-iith/FRR-Attacks/assets/42262349/ac99c0de-42be-41ea-ab5a-8943f4c2af1c" width="400" height="300">

## Key Elements
- Implementation of attack mechanism for two fast reroute systems - [Blink](https://github.com/nsg-ethz/Blink) and [Routescout](https://conferences.sigcomm.org/sosr/2021/papers/s21.pdf).
- Integration of flow feature collection logic with fast reroute systems
- Integration of realistic traffic traces using the CAIDA dataset
- Implementation of the proposed detection mechanism

## Getting Started
To get started with using the attack detection mechanism, follow these steps:
1. Clone this repository to your local machine.
2. Navigate to the `src` directory.
3. Follow the instructions in the documentation to set up and configure the detection mechanism.
4. Integrate the mechanism with your fast reroute system for continuous monitoring.

## Usage
Review the `dependencies\` before deploying the attack detection mechanism in your network environment. Instructions present in the README files.

## Contributions
We welcome contributions from researchers and practitioners interested in enhancing the security of fast reroute systems. Whether it's code improvements, additional attack scenarios, or further validation, your input is valuable in fortifying network resilience against malicious threats.

## Acknowledgement
This work is supported by the National Security Council Secretariat (NSCS), India, and the Prime Minister's Research Fellowship (PMRF) program, India.

## Citation
If you find our work useful in your research, please feel free to cite our paper.

Additionally, you may find our following work relevant:

SA Harish, Divya Pathak, Mahanth Kumar Valluri, Sree Prathyush Chinta, Amogh Bedarakota, Rinku Shah, Praveen Tammana. "Securing In-Network Fast Control Loop Systems from Adversarial Attacks." In *16th International Conference on COMmunication Systems & NETworkS (COMSNETS)*, IEEE, 2024. [Link to paper](https://ieeexplore.ieee.org/abstract/document/10427291)

## Get Involved
Feel free to raise issues, submit pull requests, or reach out to us [here](praveent@cse.iith.ac.in) with any questions or suggestions. 

