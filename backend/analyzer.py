import networkx as nx
from kubernetes import client, config
import json

class K8sAnalyzer:
    def __init__(self):
        try:
            config.load_kube_config()
        except Exception as e:
            print(f"Warning: Could not load local kubeconfig: {e}")
        
        self.v1 = client.CoreV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.graph = nx.DiGraph()

    def scan_cluster(self):
        print("[*] Scanning Kubernetes cluster resources...")
        
        # 1. Add Master Node root target
        self.graph.add_node("MasterNode", type="Target", risk="CRITICAL")

        # 2. Collect Pods
        try:
            pods = self.v1.list_pod_for_all_namespaces().items
        except Exception as e:
            print(f"Error listing pods: {e}")
            return self.graph

        for pod in pods:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            sa = pod.spec.service_account_name
            
            # Check for security risks
            is_privileged = False
            if pod.spec.containers:
                for container in pod.spec.containers:
                    sc = container.security_context
                    if sc and sc.privileged:
                        is_privileged = True

            pod_id = f"Pod:{ns}/{name}"
            risk = "HIGH" if is_privileged else "LOW"
            self.graph.add_node(pod_id, type="Pod", namespace=ns, privileged=is_privileged, risk=risk, service_account=sa)

            # Link Pod to its ServiceAccount
            sa_id = f"ServiceAccount:{ns}/{sa}"
            self.graph.add_node(sa_id, type="ServiceAccount")
            self.graph.add_edge(pod_id, sa_id, relation="uses_service_account")

            # If privileged, link directly to potential node compromise
            if is_privileged:
                self.graph.add_edge(pod_id, "MasterNode", relation="privileged_container_escape", weight=1)

        # 3. Collect ClusterRoleBindings & RoleBindings to find dangerous privileges
        try:
            crbs = self.rbac_v1.list_cluster_role_binding().items
            for crb in crbs:
                role_name = crb.role_ref.name
                if role_name in ["cluster-admin", "admin"]:
                    for subject in (crb.subjects or []):
                        if subject.kind == "ServiceAccount":
                            sa_id = f"ServiceAccount:{subject.namespace}/{subject.name}"
                            if self.graph.has_node(sa_id):
                                # Privilege escalation path to cluster admin / master node
                                self.graph.add_edge(sa_id, "MasterNode", relation="cluster_admin_privileges", weight=1)
        except Exception as e:
            print(f"Error scanning RBAC: {e}")

        return self.graph

    def find_attack_paths(self):
        paths = []
        # Find paths from any pod to MasterNode
        pods = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'Pod']
        
        for pod in pods:
            try:
                path = nx.shortest_path(self.graph, source=pod, target="MasterNode")
                paths.append({
                    "start": pod,
                    "target": "MasterNode",
                    "path": path,
                    "hops": len(path) - 1
                })
            except nx.NetworkXNoPath:
                continue
        return paths

if __name__ == "__main__":
    analyzer = K8sAnalyzer()
    graph = analyzer.scan_cluster()
    print(f"\n[+] Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
    
    paths = analyzer.find_attack_paths()
    print(f"\n[+] Found {len(paths)} attack paths to Master Node:")
    for p in paths:
        print(f"  -> Path ({p['hops']} hops): {' -> '.join(p['path'])}")
