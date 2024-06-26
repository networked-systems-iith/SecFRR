## BLINK
Blink is a fast, data-driven data plane system that leverages TCP-induced signals to detect remote failures directly in the data plane. Blink is focused on detecting remote failures. Remote failures are frequent and slow to repair, i.e., these failures trigger control-plane-driven convergence through BGP updates on a per-router and per-prefix basis, making it impossible to converge the network within O(1 sec). Thus, blink is solely based on data plane signals. Blink does not wait for BGP updates from the control plane, thus guaranteeing to reroute within O(1 sec). 


The base for our code has been taken from the official [Blink Repository](https://github.com/nsg-ethz/Blink).
