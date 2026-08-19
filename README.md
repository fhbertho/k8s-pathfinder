# Kubernetes Microsegmentation and Attack Path Visualizer

A security analysis and visualization tool designed to evaluate Kubernetes cluster posture, discover lateral movement vectors, compute multi-hop attack graphs targeting the Master Node, and simulate microsegmentation policies.

## Overview

In modern containerized environments, flat network topologies and permissive Role-Based Access Control (RBAC) configurations frequently allow internal threat actors or compromised pods to escalate privileges and compromise the control plane (Master Node). 

This project statically and dynamically analyzes Kubernetes manifests, API server permissions, and network policies to:
1. Parse Kubernetes cluster configurations and runtime state.
2. Construct a directed graph representing entities (Pods, ServiceAccounts, Roles, ClusterRoles, Nodes, Secrets) and their relationships.
3. Compute feasible attack paths leading to cluster takeover.
4. Simulate and validate microsegmentation rules to enforce the principle of least privilege.

---

## Core Architecture

```
+------------------------------------------------------------+
|                      Input Sources                         |
|   (K8s Manifests YAMLs / Live API Server / RBAC / NetPol)   |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
|                    Graph Engine & Parser                   |
|     - Entities: Pod, ServiceAccount, Role, Node, Secret    |
|     - Edges: EXEC_EXEC, TOKEN_MOUNT, RBAC_BIND, NET_ACCESS  |
+-----------------------------+------------------------------+
                              |
        +---------------------+---------------------+
        |                                           |
        v                                           v
+-------------------------------+           +-------------------------------+
|     Attack Path Analyzer      |           |  Microsegmentation Simulator  |
| - Dijkstra / Shortest Path    |           | - NetworkPolicy Enforcement   |
| - Privilege Escalation Matrix |           | - Isolation Verification      |
+-------------------------------+           +-------------------------------+
        |                                           |
        +---------------------+---------------------+
                              |
                              v
+------------------------------------------------------------+
|                    Output & Reporting                      |
|       - CLI Report Output / JSON Graph Export / UI         |
+------------------------------------------------------------+
```

---

## Key Features

- **Automated RBAC and Service Account Mapping**: Identifies over-privileged Roles and ClusterRoles bound to default or vulnerable ServiceAccounts.
- **Attack Graph Generation**: Models lateral movement scenarios including container escape vectors, credential harvesting from mounted secrets, and excessive API permissions (`create pods/exec`, `bind`, `impersonate`).
- **Microsegmentation Policy Evaluator**: Tests current namespace isolation and NetworkPolicies to detect segmentation gaps and lateral traffic leakage.
- **Master Node Compromise Scoring**: Calculates a deterministic risk score for every entry point based on privilege depth and path length to control plane access.

---

## Tech Stack

- **Language**: Python 3.10+ / Go (Modular parsing components)
- **Graph Processing**: NetworkX
- **Kubernetes SDK**: `kubernetes` python client / YAML parsers (`PyYAML`)
- **Interface**: CLI with structured JSON / HTML export options

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Access to a Kubernetes cluster (minikube, kind, or remote test cluster) or a directory containing Kubernetes deployment manifests.

### Clone and Install Dependencies
```bash
git clone https://github.com/your-username/k8s-attack-path-visualizer.git
cd k8s-attack-path-visualizer

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### 1. Analyzing Static Manifests
Scan a directory containing Kubernetes manifest files to map potential privilege escalation and network exposure:
```bash
python main.py analyze --manifests /path/to/k8s/manifests/ --output report.json
```

### 2. Analyzing a Live Cluster (Kubeconfig)
Connect directly to a target cluster using your current context to evaluate real-time RBAC and topology:
```bash
python main.py scan --kubeconfig ~/.kube/config --target-namespace default
```

### 3. Simulating Microsegmentation Remediation
Test proposed NetworkPolicies against the computed attack graph to verify closure of lateral movement channels:
```bash
python main.py simulate --graph report.json --policies /path/to/policies/
```

---

## Example Output

```text
[INFO] Initializing K8s Cluster Security Audit...
[INFO] Loaded 42 Pods, 14 ServiceAccounts, 8 ClusterRoles, 3 NetworkPolicies.
[WARN] Vulnerability Found: ServiceAccount 'default:ci-runner' bound to ClusterRole 'cluster-admin' via RoleBinding.
[WARN] Attack Path Discovered:
  [Pod: web-app-pod] 
    --> (Token Mount / Secret Extraction) 
  [ServiceAccount: ci-runner] 
    --> (RBAC ClusterRoleBinding: cluster-admin) 
  [Target: Master Node / API Server Control Plane]
[SUMMARY] Risk Score: CRITICAL (Path Length: 2 hops)
```

---

## Roadmap

- [ ] Implementation of eBPF-based runtime traffic discovery to supplement static topology mapping.
- [ ] Integration with OPA / Gatekeeper to automatically generate remediation policies.
- [ ] Web-based UI dashboard using Cytoscape.js for interactive attack graph exploration.

---

## Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request for review.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
