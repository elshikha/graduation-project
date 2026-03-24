import uuid

def uid(prefix, identifier=None):
    if identifier:
        return f"{prefix}_{identifier}"
    import uuid
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

class BehaviorGraphBuilder:
    def __init__(self, data):
        self.data = data
        self.nodes = {}
        self.edges = []

    def add_node(self, node_type, label, evidence, identifier=None):
        node_id = uid(node_type, identifier)
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "evidence": evidence
        }
        return node_id

    def add_edge(self, edge_type, source, target, evidence):
        edge_id = uid("edge")
        self.edges.append({
            "id": edge_id,
            "type": edge_type,
            "source": source,
            "target": target,
            "evidence": evidence
        })

    def build(self):
        pid_to_node = {}

        # Processes
        for idx, proc in enumerate(self.data.get("processes", [])):
            node_id = self.add_node(
                "process",
                f"{proc['name']} (PID {proc['pid']})",
                {"record": proc},
                identifier=proc['pid']
            )
            pid_to_node[proc["pid"]] = node_id

        # Parent-child
        for proc in self.data.get("processes", []):
            if proc.get("ppid") in pid_to_node:
                self.add_edge(
                    "spawned",
                    pid_to_node[proc["ppid"]],
                    pid_to_node[proc["pid"]],
                    {"timestamp": proc["start_time"]}
                )

        # File events
        for evt in self.data.get("file_events", []):
            file_node = self.add_node("file", evt["path"], {"record": evt}, identifier=evt["path"].replace("\\", "_").replace(":", ""))
            self.add_edge(
                evt["action"],
                pid_to_node[evt["process_pid"]],
                file_node,
                {"timestamp": evt["timestamp"]}
            )

        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }
